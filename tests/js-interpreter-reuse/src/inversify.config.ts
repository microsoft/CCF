import { Container, interfaces } from "inversify";
import { SlowConstructorService } from "./SlowConstructorService";

const container = new Container();

container
  .bind<SlowConstructorService>(SlowConstructorService.ServiceId)
  .to(SlowConstructorService)
  .inSingletonScope();

export { container };
