const singletons = new Map<string, unknown>();

export function getSingleton<T>(key: string, factory: () => T): T {
  if (!singletons.has(key)) {
    singletons.set(key, factory());
  }

  return singletons.get(key) as T;
}
