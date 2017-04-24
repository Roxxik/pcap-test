use core::mem;

use futures::{Future, Poll, IntoFuture, Async};
use futures::stream::Stream;
pub trait ScanableStream: Stream {
    fn scan<F, T, Fut>(self, init: T, f: F) -> Scan<Self, F, Fut, T>
        where F: FnMut(T, Self::Item) -> Fut,
            Fut: IntoFuture<Item=T>,
            Self::Error: From<Fut::Error>,
            Self: Sized;
}

pub struct ScanableStreamWrapper<S>(pub S);

impl<S:Stream> Stream for ScanableStreamWrapper<S> {
    type Item = S::Item;
    type Error = S::Error;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.0.poll()
    }
}

impl<S: Stream> ScanableStream for ScanableStreamWrapper<S> {
    fn scan<F, T, Fut>(self, init: T, f: F) -> Scan<Self, F, Fut, T>
        where F: FnMut(T, Self::Item) -> Fut,
            Fut: IntoFuture<Item=T>,
            Self::Error: From<Fut::Error>,
            Self: Sized
    {
        new(self,f, init)
    }
}

/// A future used to collect all the results of a stream into one generic type.
///
/// This future is returned by the `Stream::fold` method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Scan<S, F: ?Sized, Fut, T> where Fut: IntoFuture {
    stream: S,
    state: State<T, Fut::Future>,
    f: F,
}

#[derive(Debug)]
enum State<T, F> {
    Empty,
    Ready(T),
    Processing(F),
}

pub fn new<S, F, Fut, T>(s: S, f: F, t: T) -> Scan<S, F, Fut, T>
    where S: Stream,
          F: FnMut(T, S::Item) -> Fut,
          Fut: IntoFuture<Item = T>,
          S::Error: From<Fut::Error>,
{
    Scan {
        stream: s,
        f: f,
        state: State::Ready(t),
    }
}


impl<S, F, Fut, T> Stream for Scan<S, F, Fut, T>
    where S: Stream,
          F: FnMut(T, S::Item) -> Fut,
          Fut: IntoFuture<Item = T>,
          S::Error: From<Fut::Error>,
          T: Clone,
{
    type Item = T;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<T>, S::Error> {
        loop {
            match mem::replace(&mut self.state, State::Empty) {
                State::Empty => return Ok(Async::Ready(None)),
                State::Ready(state) => {
                    match self.stream.poll()? {
                        Async::Ready(Some(e)) => {
                            let future = (self.f)(state.clone(), e);
                            let future = future.into_future();
                            self.state = State::Processing(future);
                            return Ok(Async::Ready(Some(state)))
                        }
                        Async::Ready(None) => return Ok(Async::Ready(Some(state))),
                        Async::NotReady    => {
                            self.state = State::Ready(state);
                            return Ok(Async::NotReady)
                        }
                    }
                }
                State::Processing(mut fut) => {
                    match fut.poll()? {
                        Async::Ready(state) => self.state = State::Ready(state),
                        Async::NotReady => {
                            self.state = State::Processing(fut);
                            return Ok(Async::NotReady)
                        }
                    }
                }
            }
        }
    }
}
