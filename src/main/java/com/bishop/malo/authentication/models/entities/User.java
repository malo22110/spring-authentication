package com.bishop.malo.authentication.models.entities;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;

import org.springframework.data.jpa.domain.AbstractPersistable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

@Entity
public class User extends AbstractPersistable<Long> implements UserDetails {

	private static final long serialVersionUID = -435688525188127137L;

	private String username;
	private String email;
	private String password;
	
	private boolean accountNonExpired;
	private boolean accountNonLocked;
	private boolean credentialsNonExpired;
	private boolean enabled;
	

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "users_roles",  
			   joinColumns = @JoinColumn(
			   name = "user_id", referencedColumnName = "id"), 
			   inverseJoinColumns = @JoinColumn(
			   name = "role_id", referencedColumnName = "id")) 
	private Collection<Role> roles;
	
	public User() {
		super();
		this.accountNonExpired = true;
		this.accountNonLocked = true;
		this.credentialsNonExpired = true;
		this.enabled = true;
		
	}

	@Override
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
	
	@Override
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

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		 final Set<SimpleGrantedAuthority> _grntdAuths = new HashSet<SimpleGrantedAuthority>();

	     Collection<Role> _roles = null;

	     if (this!=null) {
	             _roles = this.getRoles();
	     }

	     if (_roles!=null) {
	             for (Role _role : _roles) {
	                     _grntdAuths.add(new SimpleGrantedAuthority(_role.getAuthority()));
	             }
	     }

	     return _grntdAuths;
	}

	@Override
	public boolean isAccountNonExpired() {
		return this.accountNonExpired;
	}
	
	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return this.accountNonLocked;
	}
	
	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return this.credentialsNonExpired;
	}
	
	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	
}
