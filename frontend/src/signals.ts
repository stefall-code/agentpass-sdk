type Listener<T> = (value: T, prev: T) => void;

export class Signal<T> {
  private _value: T;
  private _listeners: Set<Listener<T>> = new Set();

  constructor(initial: T) {
    this._value = initial;
  }

  get value(): T {
    return this._value;
  }

  set value(next: T) {
    if (Object.is(this._value, next)) return;
    const prev = this._value;
    this._value = next;
    for (const fn of this._listeners) {
      try { fn(next, prev); } catch { /* swallow */ }
    }
  }

  subscribe(fn: Listener<T>): () => void {
    this._listeners.add(fn);
    return () => { this._listeners.delete(fn); };
  }

  map<U>(transform: (v: T) => U): ReadonlySignal<U> {
    const derived = new ReadonlySignal(transform(this._value));
    this.subscribe((v) => { derived._setValue(transform(v)); });
    return derived;
  }
}

export class ReadonlySignal<T> {
  protected _value: T;
  private _listeners: Set<Listener<T>> = new Set();

  constructor(initial: T) {
    this._value = initial;
  }

  get value(): T {
    return this._value;
  }

  protected _setValue(next: T): void {
    if (Object.is(this._value, next)) return;
    const prev = this._value;
    this._value = next;
    for (const fn of this._listeners) {
      try { fn(next, prev); } catch { /* swallow */ }
    }
  }

  subscribe(fn: Listener<T>): () => void {
    this._listeners.add(fn);
    return () => { this._listeners.delete(fn); };
  }
}

export function effect<T>(signal: Signal<T> | ReadonlySignal<T>, fn: (v: T) => void): () => void {
  fn(signal.value);
  return signal.subscribe(fn);
}

export function computed<T, U>(signal: Signal<T>, transform: (v: T) => U): ReadonlySignal<U> {
  return signal.map(transform);
}
