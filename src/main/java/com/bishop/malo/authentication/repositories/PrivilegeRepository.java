package com.bishop.malo.authentication.repositories;

import java.io.Serializable;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.bishop.malo.authentication.entities.Privilege;


@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege, Serializable> {
	public Privilege findByName(String name);
}
