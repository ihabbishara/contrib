
import {
   WiServiceContribution
} from "wi-studio/app/contrib/wi-contrib";
import { NgModule } from "@angular/core";
import { CommonModule } from "@angular/common";
import { HttpModule, Http } from "@angular/http";
import { httpinvokeHandler } from "./httpinvokeHandler";
@NgModule({
  imports: [
    CommonModule,
HttpModule
  ],
  exports: [],
  declarations: [],
  entryComponents: [],
  providers: [
    { provide: WiServiceContribution, useClass: httpinvokeHandler}
  ],
  bootstrap: []
})
export default class httpinvokeModule {

}
