// validators/PasswordMismatch.ts
import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
  registerDecorator,
  ValidationOptions,
} from 'class-validator';

@ValidatorConstraint({ name: 'passwordMismatch', async: false })
export class PasswordMismatchConstraint
  implements ValidatorConstraintInterface
{
  validate(newPassword: any, args: ValidationArguments) {
    const object = args.object as any;
    return newPassword !== object.currentPassword;
  }

  defaultMessage() {
    return `New password must be different from current password`;
  }
}

export function PasswordMismatch(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [],
      validator: PasswordMismatchConstraint,
    });
  };
}
