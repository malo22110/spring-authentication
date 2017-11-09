package com.bishop.malo.authentication.models.entities;

import java.util.Collection;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;

import org.springframework.security.core.GrantedAuthority;


@Entity
public class Role implements GrantedAuthority {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	private String name;
//
	@ManyToMany
	@JoinTable(name = "roles_privileges", 
	   joinColumns = @JoinColumn(
	   name = "role_id", referencedColumnName = "id"), 
	   inverseJoinColumns = @JoinColumn(
	   name = "privilege_id", referencedColumnName = "id"))
	private Collection<Privilege> privileges; 
	
	
	
	public Role() {
		super();
	}

	public Role(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Collection<Privilege> getPrivileges() {
		return this.privileges;
	}

	public void setPrivileges(Collection<Privilege> privileges) {
		this.privileges = privileges;
	}

	@Override
	public String getAuthority() {
		return this.name;
	}
}


