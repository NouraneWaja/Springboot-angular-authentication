import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticationService } from '../../services/services';
import { RegistrationRequest } from '../../services/models';
import{FormsModule} from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [FormsModule,CommonModule],
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent {
  registerRequest: RegistrationRequest = {email: '', firstname: '', lastname: '', password: ''};
  errorMsg: Array<string> = [];

  constructor( private router: Router, private authService: AuthenticationService ) {}

  login() {
    this.router.navigate(['login']);
  }

  register() {
    this.errorMsg = [];
      
    this.authService.register({ body: this.registerRequest })
      .subscribe(
        (response: any) => {
          this.router.navigate(['activate-account']);
        },
        (error: HttpErrorResponse) => {
            this.errorMsg = error.error.validationError;
        }
      );
  }
}
