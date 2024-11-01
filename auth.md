Here’s a complete workflow for implementing a role-based management system in a portal that hosts multiple applications. This includes authentication, authorization, and role management with sample code for each step.


---

Workflow Overview

1. Authentication and User Identity: Authenticate users with a central identity provider (using JWT).


2. Role and Permission Management: Manage user roles and permissions with API endpoints in each app.


3. Role-Based UI and API Authorization: Control access based on user roles within each app.




---

Step-by-Step Implementation

1. Authentication (Centralized with JWT)

Example using Azure AD B2C or Auth0:

1. User logs in through a central identity provider, which issues a JWT on successful login.


2. The portal receives the token, stores it, and passes it to each application as needed.



Login Component (Angular)

// login.component.ts
import { Component } from '@angular/core';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-login',
  template: `<button (click)="login()">Login</button>`
})
export class LoginComponent {
  constructor(private authService: AuthService) {}

  login() {
    this.authService.login(); // Redirect to identity provider login
  }
}

AuthService to handle authentication with an identity provider

// auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private token: string | null = null;

  constructor(private http: HttpClient) {}

  login() {
    // Redirect to authentication provider (e.g., Azure AD B2C)
    window.location.href = 'https://your-identity-provider.com/login';
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('authToken', token);
  }

  getToken() {
    return this.token || localStorage.getItem('authToken');
  }

  isLoggedIn() {
    return !!this.getToken();
  }
}


---

2. Role Management API (Backend)

Each application’s backend service should define API endpoints to manage roles and permissions.

RoleController (ASP.NET Core)

// RoleController.cs
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

[ApiController]
[Route("api/roles")]
public class RoleController : ControllerBase
{
    private readonly RoleService _roleService;

    public RoleController(RoleService roleService)
    {
        _roleService = roleService;
    }

    [HttpGet]
    public ActionResult<IEnumerable<Role>> GetRoles() => Ok(_roleService.GetAllRoles());

    [HttpPost]
    public ActionResult CreateRole([FromBody] Role role)
    {
        _roleService.CreateRole(role);
        return Ok();
    }

    [HttpPut("{id}")]
    public ActionResult UpdateRole(int id, [FromBody] Role role)
    {
        _roleService.UpdateRole(id, role);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public ActionResult DeleteRole(int id)
    {
        _roleService.DeleteRole(id);
        return NoContent();
    }
}

RoleService (ASP.NET Core)

// RoleService.cs
using System.Collections.Generic;

public class RoleService
{
    public IEnumerable<Role> GetAllRoles() { /* retrieve roles */ }
    public void CreateRole(Role role) { /* create role */ }
    public void UpdateRole(int id, Role role) { /* update role */ }
    public void DeleteRole(int id) { /* delete role */ }
}

Role and Permission Models

public class Role {
    public int Id { get; set; }
    public string Name { get; set; }
}

public class Permission {
    public int Id { get; set; }
    public string Name { get; set; }
}


---

3. Token-Based User Context

Each application needs to verify the token and extract user information to apply roles and permissions.

JWT Middleware (ASP.NET Core)

Add JWT authentication middleware in Startup.cs:

public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication("Bearer")
        .AddJwtBearer(options =>
        {
            options.Authority = "https://your-identity-provider.com/";
            options.Audience = "your-audience";
        });
}

Add [Authorize] to secure endpoints.

Extracting User Role from JWT

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ResourceController : ControllerBase
{
    [HttpGet]
    public IActionResult GetResource()
    {
        var role = User.FindFirst("role")?.Value; // Extract role from JWT
        if (role == "Admin")
        {
            return Ok("Admin Access Granted");
        }
        return Unauthorized("Access Denied");
    }
}


---

4. Angular UI Authorization Based on Roles

Control access within the Angular app by conditionally rendering components based on roles.

Role Guard (Angular)

// role.guard.ts
import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class RoleGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  canActivate(): boolean {
    const user = this.authService.getUser();
    if (user && user.role === 'Admin') {
      return true;
    }
    this.router.navigate(['unauthorized']);
    return false;
  }
}

Conditional UI Elements

<!-- Only visible to admins -->
<button *ngIf="user.role === 'Admin'" (click)="manageRoles()">Manage Roles</button>


---

5. Role Management UI (Angular)

Provide an Angular component to manage roles and permissions.

RoleManagementComponent

// role-management.component.ts
import { Component, OnInit } from '@angular/core';
import { RoleService } from '../services/role.service';

@Component({
  selector: 'app-role-management',
  templateUrl: './role-management.component.html',
})
export class RoleManagementComponent implements OnInit {
  roles: any[] = [];

  constructor(private roleService: RoleService) {}

  ngOnInit() {
    this.roleService.getRoles().subscribe((roles) => (this.roles = roles));
  }

  addRole(roleName: string) {
    this.roleService.createRole(roleName).subscribe(() => this.ngOnInit());
  }
}

Role Service for API Integration

// role.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class RoleService {
  private apiUrl = '/api/roles';

  constructor(private http: HttpClient) {}

  getRoles() {
    return this.http.get(`${this.apiUrl}`);
  }

  createRole(roleName: string) {
    return this.http.post(`${this.apiUrl}`, { name: roleName });
  }
}


---

6. Testing the System

1. Login and Token Retrieval: Verify users can log in and obtain a JWT.


2. API Role Enforcement: Test API responses based on user roles.


3. UI Authorization: Check role-based visibility for different UI elements.


4. Role Management: Ensure admins can add/remove roles and permissions effectively.




---

This setup creates a secure, role-based management system with centralized authentication, role-based API protection, and UI-level control over access and functionality. It’s flexible for scaling with multiple applications and provides a seamless experience for users within the portal.

