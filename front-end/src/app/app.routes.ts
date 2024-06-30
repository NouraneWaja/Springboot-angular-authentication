import { Routes } from '@angular/router';
import { LoginComponent } from './pages/login/login.component';
import { RegisterComponent } from './pages/register/register.component';
import { ActivateAccountComponent } from './pages/activate-account/activate-account.component';
import { HomeComponent } from './pages/home/home.component';

export const routes: Routes = [
    {path:'', redirectTo: '/register', pathMatch: 'full'},
    { path: 'login', component:LoginComponent},
    { path: 'register', component:RegisterComponent},
    { path: 'activate-account', component:ActivateAccountComponent},
    { path: 'home', component:HomeComponent}
];
