package com.bishop.malo.authentication.services;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bishop.malo.authentication.entities.Privilege;
import com.bishop.malo.authentication.entities.Role;
import com.bishop.malo.authentication.entities.User;
import com.bishop.malo.authentication.repositories.RoleRepository;
import com.bishop.malo.authentication.repositories.UserRepository;

@Service("userDetailsService")
@Transactional
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
  
    @Autowired
    private MessageSource messages;
  
    @Autowired
    private RoleRepository roleRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username)
      throws UsernameNotFoundException {
  
        User user = userRepository.findByUsername(username);
        
        if (user == null) {        	
            return new org.springframework.security.core.userdetails.User(
              " ", " ", true, true, true, true, 
              getAuthorities((Collection<Role>) Arrays.asList(
                roleRepository.findByName("ROLE_USER"))));
        }
 
        return new org.springframework.security.core.userdetails.User(
          user.getEmail(), user.getPassword(), user.isEnabled(), true, true, 
          true, getAuthorities(user.getRoles()));
    }
 
    private Collection<? extends GrantedAuthority> getAuthorities(Collection<Role> roles) {
  
        return getGrantedAuthorities(getPrivileges(roles));
    }
 
    private List<String> getPrivileges(Collection<Role> roles) {
  
        List<String> privileges = new ArrayList<>();
        List<Privilege> collection = new ArrayList<>();
        for (Role role : roles) {
            collection.addAll(role.getPrivileges());
        }
        for (Privilege item : collection) {
            privileges.add(item.getName());
        }
        return privileges;
    }
 
    private List<GrantedAuthority> getGrantedAuthorities(List<String> privileges) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String privilege : privileges) {
            authorities.add(new SimpleGrantedAuthority(privilege));
        }
        return authorities;
    }

}
