
import {Injectable, Injector, Inject} from "@angular/core";
import {Http} from "@angular/http";
import {Observable} from "rxjs/Observable";
import {
    WiContrib,
    WiServiceHandlerContribution,
    IContributionTypes,
    ActionResult,
    IActionResult,
    WiContribModelService,
    IFieldDefinition,
    IActivityContribution
} from "wi-studio/app/contrib/wi-contrib";
import { IValidationResult, ValidationResult } from "wi-studio/common/models/validation";

@WiContrib({})
@Injectable()
export class httpinvokeHandler extends WiServiceHandlerContribution {
    constructor( @Inject(Injector) injector) {
        super(injector);
    }

    value = (fieldName: string, context: IActivityContribution): Observable<any> | any => {
        return null;
    }

    validate = (fieldName: string, context: IActivityContribution): Observable<IValidationResult> | IValidationResult => {
        if (fieldName === "method") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let selectMethodField: IFieldDefinition = context.getField("selectMethod");
            let methodField: IFieldDefinition = context.getField("method");
            if (selectMethodField.value && selectMethodField.value === true) {
                if (methodField.display && methodField.display.visible == false) {
                    vresult.setVisible(true);
                }
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        } else if (fieldName === "additionalHeaders") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let additionalHeadersField: IFieldDefinition = context.getField(fieldName);
            let arrHeaderNamesTmp: any[] = [];
            let errMessage: string = "";
            let additionalHeadersParsed: any = {};

            try {
                additionalHeadersParsed = JSON.parse(additionalHeadersField.value.value);
            } catch (e) { }

            for (let attr of additionalHeadersParsed) {
                if (!attr.headerName) {
                    errMessage = "Header Name should not be empty";
                    vresult.setError("HTTP-Invoke-1000", errMessage);
                    vresult.setValid(false);
                    break;
                } else {
                    for (let headName of arrHeaderNamesTmp) {
                        if (headName === attr.headerName) {
                            errMessage = "Header Name \'" + attr.headerName + "\' already exists";
                            vresult.setError("HTTP-Invoke-1000", errMessage);
                            vresult.setValid(false);
                            break;
                        }
                    }
                    arrHeaderNamesTmp.push(attr.headerName);
                }
            }
            return vresult;
        }
        return null;
    }
}
