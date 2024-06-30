import { Component } from '@angular/core';
import{FormsModule} from '@angular/forms';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import {AuthenticationService} from '../../services/services/authentication.service';
import {AuthenticationRequest} from '../../services/models/authentication-request';
import { HttpErrorResponse } from '@angular/common/http';
import { TokenService } from '../../services/token/token.service';



@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss',
})
export class LoginComponent {

  authRequest: AuthenticationRequest={email:'', password:''};
  errorMsg: Array<string>=[];

  constructor(private router: Router , private authService: AuthenticationService,private tokenService:TokenService ){

  } 


  register() {
    this.router.navigate(['register']);
  }
  login() {
    this.errorMsg = []; 
    this.authService.authenticate({ body: this.authRequest })
      .subscribe(
        (response: any) => {
          this.tokenService.token=response.token as string;
          this.router.navigate(['home']);
        },
        (error: HttpErrorResponse) => {
          if (error.error.validationError) {
            this.errorMsg = error.error.validationError;
          } else {
            this.errorMsg.push(error.error.error);
          } 
        }
      );
  }

}
