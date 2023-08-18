import { injectable } from "inversify";
import { fibonacci } from "./bad_fib";
import "reflect-metadata";

@injectable()
export class SlowConstructorService {
  static ServiceId = "SlowConstructorService";

  constructor() {
    console.log("  Starting slow construction");
    console.log(`    fibonacci(25) = ${fibonacci(25)}`);
    console.log("  Completed slow construction");
  }
}
