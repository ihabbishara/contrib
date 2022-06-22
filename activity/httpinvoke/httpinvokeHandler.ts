
import {Injectable, Injector, Inject} from "@angular/core";
import {Http} from "@angular/httpinvoke";
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
        }
    }
}
