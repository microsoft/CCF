import { injectable } from "inversify";
import { fibonacci } from "./bad_fib";
import "reflect-metadata";

@injectable()
export class SlowConstructorService {
  static ServiceId = "SlowConstructorService";

  constructor() {
    console.log("  Starting slow construction");
    console.log(`    fibonacci(32) = ${fibonacci(32)}`);
    console.log("  Completed slow construction");
  }
}
