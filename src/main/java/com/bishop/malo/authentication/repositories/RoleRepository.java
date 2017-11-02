package com.bishop.malo.authentication.repositories;

import java.io.Serializable;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.bishop.malo.authentication.entities.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Serializable> {
	public Role findByName(String name);
	public Set<Role> findRoleById(Long id);
}
