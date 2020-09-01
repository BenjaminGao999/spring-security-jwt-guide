package github.javaguide.springsecurityjwtguide.system.web.controller;

import com.google.common.collect.Maps;
import github.javaguide.springsecurityjwtguide.security.constants.SecurityConstants;
import github.javaguide.springsecurityjwtguide.security.entity.JwtUser;
import github.javaguide.springsecurityjwtguide.security.utils.CurrentUserUtils;
import github.javaguide.springsecurityjwtguide.security.utils.JwtTokenUtils;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import github.javaguide.springsecurityjwtguide.system.web.representation.UserRepresentation;
import github.javaguide.springsecurityjwtguide.system.web.request.UserRegisterRequest;
import github.javaguide.springsecurityjwtguide.system.web.request.UserUpdateRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author shuang.kou
 */
@RestController
//@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@RequestMapping("api/users")
@Slf4j
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private CurrentUserUtils currentUserUtils;

    @Autowired
    AuthenticationManager authenticationManager;


    @PostMapping("/sign-up")
    public ResponseEntity signUp(@RequestBody @Valid UserRegisterRequest userRegisterRequest) {
        userService.save(userRegisterRequest);
        Map<String, Object> body = Maps.newHashMap();
        body.put("code", 0);
        return ResponseEntity.ok(body);
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_MANAGER','ROLE_ADMIN')")
    public ResponseEntity<Page<UserRepresentation>> getAllUser(@RequestParam(value = "pageNum", defaultValue = "0") int pageNum, @RequestParam(value = "pageSize", defaultValue = "10") int pageSize) {
        System.out.println("当前访问该接口的用户为：" + currentUserUtils.getCurrentUser().getUserName());
        Page<UserRepresentation> allUser = userService.getAll(pageNum, pageSize);
        return ResponseEntity.ok().body(allUser);
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity<Void> update(@RequestBody @Valid UserUpdateRequest userUpdateRequest) {
        userService.update(userUpdateRequest);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity<Void> deleteUserByUserName(@RequestParam("username") String username) {
        userService.delete(username);
        return ResponseEntity.ok().build();
    }


    @PostMapping("doLogin")
    public ResponseEntity doLogin(HttpServletRequest request, HttpServletResponse response,
                                  @RequestParam("userName") String userName, @RequestParam("password") String password) {
        Map<String, Object> body = Maps.newHashMap();

        HttpHeaders httpHeaders = new HttpHeaders();

        try {
            // 内部登录请求
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(userName, password, AuthorityUtils.commaSeparatedStringToAuthorityList(""));


            // 验证
            Authentication auth = authenticationManager.authenticate(authRequest);


            SecurityContextHolder.getContext().setAuthentication(auth);

            body.put("code", 0);


            JwtUser jwtUser = (JwtUser) auth.getPrincipal();
            List<String> authorities = jwtUser.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            // 创建 Token
            String token = JwtTokenUtils.createToken(jwtUser.getUsername(), authorities, false);

            httpHeaders.set(SecurityConstants.TOKEN_HEADER, token);


        } catch (AuthenticationException e) {

            body.put("code", -1);
        }

        return ResponseEntity.status(HttpStatus.OK).headers(httpHeaders).body(body);
    }

}
