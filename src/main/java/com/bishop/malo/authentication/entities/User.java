package com.bishop.malo.authentication.entities;

import java.util.Collection;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;

import org.springframework.data.jpa.domain.AbstractPersistable;

@Entity
public class User extends AbstractPersistable<Long> {

	private static final long serialVersionUID = -435688525188127137L;

	private String username;
	private String email;
	private String password;

	private boolean enabled;

	private boolean tokenExpired;

	@ManyToMany
	@JoinTable(name = "users_roles", 
			   joinColumns = @JoinColumn(
			   name = "user_id", referencedColumnName = "id"), 
			   inverseJoinColumns = @JoinColumn(
			   name = "role_id", referencedColumnName = "id")) 
	private Collection<Role> roles;
	
	public User() {
		super();
	}

	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}	
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public Collection<Role> getRoles() {
		return roles;
	}
	public void setRoles(Collection<Role> roles) {
		this.roles = roles;
	}
	public boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public boolean isTokenExpired() {
		return tokenExpired;
	}
	public void setTokenExpired(boolean tokenExpired) {
		this.tokenExpired = tokenExpired;
	}
}
