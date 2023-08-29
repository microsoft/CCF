import { Container, interfaces } from "inversify";
import { SlowConstructorService } from "./SlowConstructorService";

const container = new Container();

container
  .bind<SlowConstructorService>(SlowConstructorService.ServiceId)
  .to(SlowConstructorService)
  // NB: The latter is critical - we only get cache reuse benefits for
  // state which is actually cached, such as singleton bindings.
  .inSingletonScope();

export { container };
