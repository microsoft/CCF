export function func_caching(request) {
  const s = "<func_caching_placeholder>";
  console.log(`Executing with s: ${s}`);

  return { body: s };
}
