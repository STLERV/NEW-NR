import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class MensajeService {

  constructor(private http: HttpClient) { }

  
  readonly URLBob = 'http://localhost:3000';
  readonly URLTTP = 'http://localhost:2000';

  enviarMensaje1(mensaje: any) {

    return this.http.post(this.URLBob + '/mensaje1', { mensaje });
  }

  enviarMensaje3(mensaje: any) {

    return this.http.post(this.URLTTP + '/mensaje3', { mensaje });
  }


  avisobob()
  {

    return this.http.get(this.URLBob + '/avisobob');
  }


  dameClaveTTP() {
    return this.http.get(this.URLTTP + '/key');
  }



  dameClave() {
    return this.http.get(this.URLBob + '/key');
  }

  dameclavesPai() {
    return this.http.get(this.URLBob + '/keypai');

  }
  send(body){
    return this.http.post(this.URLBob + '/suma', body);
  }

}
