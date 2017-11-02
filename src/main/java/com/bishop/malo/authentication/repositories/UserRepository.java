package com.bishop.malo.authentication.repositories;

import java.io.Serializable;
import java.util.Collection;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.bishop.malo.authentication.entities.Role;
import com.bishop.malo.authentication.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, Serializable> {
	public User findByUsername(String username);
	public User findByEmail(String email);
}
