package com.bishop.malo.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.bishop.malo.authentication.models.entities.Privilege;
import com.bishop.malo.authentication.models.entities.Role;
import com.bishop.malo.authentication.models.entities.User;
import com.bishop.malo.authentication.repositories.PrivilegeRepository;
import com.bishop.malo.authentication.repositories.RoleRepository;
import com.bishop.malo.authentication.repositories.UserRepository;

@Component
public class InitialDataLoader implements
  ApplicationListener<ContextRefreshedEvent> {
 
    boolean alreadySetup = false;
 
    @Autowired
    private UserRepository userRepository;
  
    @Autowired
    private RoleRepository roleRepository;
  
    @Autowired
    private PrivilegeRepository privilegeRepository;
  
    @Autowired
    private PasswordEncoder passwordEncoder;
  
    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent event) {
  
        if (alreadySetup)
            return;
        Privilege readPrivilege
          = createPrivilegeIfNotFound("READ_PRIVILEGE");
        Privilege writePrivilege
          = createPrivilegeIfNotFound("WRITE_PRIVILEGE");
  
        List<Privilege> adminPrivileges = Arrays.asList(
          readPrivilege, writePrivilege);        
        createRoleIfNotFound("ROLE_ADMIN", adminPrivileges);
        createRoleIfNotFound("ROLE_USER", Arrays.asList(readPrivilege));
 
        Role adminRole = roleRepository.findByName("ROLE_ADMIN");
        User user = new User();
        user.setUsername("Test");
        user.setPassword(passwordEncoder.encode("test"));
        user.setEmail("test@test.com");
        user.setRoles(Arrays.asList(adminRole));
        user.setEnabled(true);
        userRepository.save(user);
 
        alreadySetup = true;
    }
 
    @Transactional
    private Privilege createPrivilegeIfNotFound(String name) {
  
        Privilege privilege = privilegeRepository.findByName(name);
        if (privilege == null) {
            privilege = new Privilege(name);
            privilegeRepository.save(privilege);
        }
        return privilege;
    }
 
    @Transactional
    private Role createRoleIfNotFound(
      String name, Collection<Privilege> privileges) {
  
        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
//            role.setPrivileges(privileges);
            roleRepository.save(role);
        }
        return role;
    }
}