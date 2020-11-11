export class CCFBody {
  constructor(body) {
    this.body = body; // string
  }
  text() {
    return this.body;
  }
  json() {
    return JSON.parse(this.body);
  }
  arrayBuffer() {
    return new TextEncoder().encode(this.body).buffer;
  }
}
