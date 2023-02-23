# Spring Security+jwt+redis+自定义认证逻辑 权限控制

### 1.拦截访问基本思路

![image-20221006121814243](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20221006121814243.png)

### 2.创建数据库表：角色表（应该6个表，这里只用用户表代替角色表）、权限表、路径表、角色-权限表、权限-路径表

```sql
/*
SQLyog Professional v12.14 (64 bit)
MySQL - 5.7.40 : Database - assist_silkworm_db
*********************************************************************
*/


/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE=''*/;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/`assist_silkworm_db` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `assist_silkworm_db`;

/*Table structure for table `t_path` */
# 路径表
DROP TABLE IF EXISTS `t_path`;

CREATE TABLE `t_path` (
  `path_id` bigint(19) NOT NULL COMMENT '路径表id',
  `path` varchar(200) NOT NULL COMMENT '路径名称',
  `gmt_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `gmt_modified` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`path_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

/*Data for the table `t_path` */

insert  into `t_path`(`path_id`,`path`,`gmt_created`,`gmt_modified`) values 

(1607234202607067138,'/**','2023-02-23 12:07:42','2023-02-23 12:12:47');

/*Table structure for table `t_permission` */

DROP TABLE IF EXISTS `t_permission`;
# 权限表
CREATE TABLE `t_permission` (
  `permission_id` bigint(19) NOT NULL COMMENT '主键ID',
  `permission` varchar(255) NOT NULL COMMENT '权限',
  `gmt_created` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `gmt_modified` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`permission_id`),
  UNIQUE KEY `role` (`permission`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*Data for the table `t_permission` */

insert  into `t_permission`(`permission_id`,`permission`,`gmt_created`,`gmt_modified`) values 

(1607234202607067138,'ROLE_BIG_ADMIN','2023-02-23 12:10:07','2023-02-23 12:10:07');

/*Table structure for table `t_permission_path` */
# 权限路径表
DROP TABLE IF EXISTS `t_permission_path`;

CREATE TABLE `t_permission_path` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `permission_id` bigint(19) NOT NULL COMMENT '权限Id',
  `path_id` bigint(19) NOT NULL COMMENT '权限对应的路径',
  `gmt_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `gmt_modified` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

/*Data for the table `t_permission_path` */

insert  into `t_permission_path`(`id`,`permission_id`,`path_id`,`gmt_created`,`gmt_modified`) values 

(1,1607234202607067138,1607234202607067138,'2023-02-23 12:13:59','2023-02-23 12:13:59');

/*Table structure for table `t_user` */
# 用户表
DROP TABLE IF EXISTS `t_user`;

CREATE TABLE `t_user` (
  `user_id` bigint(19) NOT NULL AUTO_INCREMENT COMMENT '主键',
  `username` varchar(100) NOT NULL COMMENT '账号',
  `password` varchar(100) NOT NULL COMMENT '密码',
  `gmt_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `gmt_modified` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  `is_del` tinyint(1) NOT NULL DEFAULT '0' COMMENT '是否删除',
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1607234202607067139 DEFAULT CHARSET=utf8;

/*Data for the table `t_user` */

insert  into `t_user`(`user_id`,`username`,`password`,`gmt_created`,`gmt_modified`,`is_del`) values 

(1607234202607067138,'admin','$2a$10$GE0hWDRIksPXpZCDtTEFP.8EKi25OQ8PPvc6Q14YzSyzpkkQzDPxW','2022-12-26 12:37:50','2023-02-23 12:09:05',0);

/*Table structure for table `t_user_permission` */

DROP TABLE IF EXISTS `t_user_permission`;
# 用户权限表
CREATE TABLE `t_user_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `user_id` bigint(19) NOT NULL COMMENT '用户Id',
  `permission_id` bigint(19) NOT NULL COMMENT '权限Id',
  `gmt_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `gmt_modified` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;

/*Data for the table `t_user_permission` */

insert  into `t_user_permission`(`id`,`user_id`,`permission_id`,`gmt_created`,`gmt_modified`) values 

(2,1607234202607067138,1607234202607067138,'2023-02-23 12:13:06','2023-02-23 12:13:06');

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

```



### 3.导入依赖

```xml
<!-- https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
    <version>2.7.4</version>
</dependency>

```

![image-20230223222442753](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20230223222442753.png)

###4.创建实现UserDestails的实现类

```java
package com.rfos.assistsilkworm.config.security;

import com.rfos.assistsilkworm.pojo.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author hjt
 * @date 2022/10/4 20:55
 * @description
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsDTO implements UserDetails {

    private User user;

    private List<String> permissionList;

    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        for (String permission : permissionList) {
            //拥有的权限名
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(permission);
            grantedAuthorityList.add(simpleGrantedAuthority);
        }
        setAuthorities(grantedAuthorityList);
        return grantedAuthorityList;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }


    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}


```

**UserDetails类：**

**UserDetails**(位于org.springframework.security.core.userdetails包下)主要和用户信息有关的接口，该接口是提供用户信息的核心接口。该接口实现仅仅存储用户的信息。后续会将该接口提供的用户信息封装到认证对象Authentication中去

```java
public interface UserDetails extends Serializable {
	
	// 权限
	// 用户的权限集， 默认需要添加ROLE_ 前缀
    Collection<? extends GrantedAuthority> getAuthorities();
	// 密码
	// 用户的加密后的密码， 不加密会使用{noop}前缀
    String getPassword();
	// 用户名
    String getUsername();
	// 帐户未过期
    boolean isAccountNonExpired();
    // 帐户未锁定
    boolean isAccountNonLocked();
	// 凭证是否过期
    boolean isCredentialsNonExpired();
	// 用户是否可用
    boolean isEnabled();
}

```

**角色表等各个表对应的实体类**

![image-20230223222708838](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20230223222708838.png)

```java
package com.rfos.assistsilkworm.pojo;

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.io.Serializable;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <p>
 * 
 * </p>
 *
 * @author rfos
 * @since 2023-02-23
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
@TableName("t_user")
@ApiModel(value="User对象", description="")
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键")
      @TableId(value = "user_id", type = IdType.ASSIGN_ID)
    private Long userId;

    @ApiModelProperty(value = "账号")
    private String username;

    @ApiModelProperty(value = "密码")
    private String password;

    @ApiModelProperty("创建时间")//创建时间由SQL完成
    @TableField(fill = FieldFill.INSERT)
    private Date gmtCreated;

    @ApiModelProperty("更新时间")//更新时间由数据库完成
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date gmtModified;

    @ApiModelProperty(value = "是否删除")
    private Boolean isDel;


}
```
```java
package com.rfos.assistsilkworm.pojo;

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import springfox.documentation.annotations.ApiIgnore;

/**
 * <p>
 * 
 * </p>
 *
 * @author rfos
 * @since 2023-02-23
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
@TableName("t_path")
@ApiModel(value="Path对象", description="")
public class Path implements Serializable {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "路径表id")
      @TableId(value = "path_id", type = IdType.ASSIGN_ID)
    private Long pathId;

    @ApiModelProperty(value = "路径名称")
    private String path;

    @ApiModelProperty("创建时间")//创建时间由SQL完成
    @TableField(fill = FieldFill.INSERT)
    private Date gmtCreated;

    @ApiModelProperty("更新时间")//更新时间由数据库完成
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date gmtModified;


}

```
```java
package com.rfos.assistsilkworm.pojo;

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.io.Serializable;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <p>
 * 
 * </p>
 *
 * @author rfos
 * @since 2023-02-23
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
@TableName("t_permission")
@ApiModel(value="Permission对象", description="")
public class Permission implements Serializable {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键ID")
      @TableId(value = "permission_id", type = IdType.ASSIGN_ID)
    private Long permissionId;

    @ApiModelProperty(value = "权限")
    private String permission;

    @ApiModelProperty("创建时间")//创建时间由SQL完成
    @TableField(fill = FieldFill.INSERT)
    private Date gmtCreated;

    @ApiModelProperty("更新时间")//更新时间由数据库完成
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date gmtModified;


}
```
```java

package com.rfos.assistsilkworm.pojo;

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.io.Serializable;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <p>
 * 
 * </p>
 *
 * @author rfos
 * @since 2023-02-23
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
@TableName("t_permission_path")
@ApiModel(value="PermissionPath对象", description="")
public class PermissionPath implements Serializable {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键ID")
      @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    @ApiModelProperty(value = "权限Id")
    private Long permissionId;

    @ApiModelProperty(value = "权限对应的路径")
    private Long pathId;

    @ApiModelProperty("创建时间")//创建时间由SQL完成
    @TableField(fill = FieldFill.INSERT)
    private Date gmtCreated;

    @ApiModelProperty("更新时间")//更新时间由数据库完成
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date gmtModified;


}
```
```java

package com.rfos.assistsilkworm.pojo;

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.io.Serializable;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <p>
 * 
 * </p>
 *
 * @author rfos
 * @since 2023-02-23
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
@TableName("t_user_permission")
@ApiModel(value="UserPermission对象", description="")
public class UserPermission implements Serializable {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键ID")
      @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    @ApiModelProperty(value = "用户Id")
    private Long userId;

    @ApiModelProperty(value = "权限Id")
    private Long permissionId;

    @ApiModelProperty("创建时间")//创建时间由SQL完成
    @TableField(fill = FieldFill.INSERT)
    private Date gmtCreated;

    @ApiModelProperty("更新时间")//更新时间由数据库完成
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date gmtModified;


}


```

### 5.创建自定义认证逻辑-UserDetailsService的实现类-UserDetailServiceImpl类

**UserDetailsService接口**

```java
package org.springframework.security.core.userdetails;
public interface UserDetailsService {
    UserDetails loadUserByUsername(String var1) throws UsernameNotFoundException;
}
```

**UserDetailServiceImpl类**

```java
package com.rfos.assistsilkworm.config.security;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.rfos.assistsilkworm.pojo.Permission;
import com.rfos.assistsilkworm.pojo.User;
import com.rfos.assistsilkworm.pojo.UserPermission;
import com.rfos.assistsilkworm.service.PermissionService;
import com.rfos.assistsilkworm.service.UserPermissionService;
import com.rfos.assistsilkworm.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author hjt
 * @date 2022/10/5 11:24
 * @description
 */
@Service("userDetailsServiceImpl")
public class UserDetailsServiceImpl implements UserDetailsService {
    //用户业务
    @Autowired
    private UserService userService;
    @Autowired
    private PermissionService permissionService;
    @Autowired
    private UserPermissionService userPermissionService;

    /*
    重写方法：
    username: 需要其数据的用户的用户名
    UsernameNotFoundException： 找不到用户的异常
    */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //获取用户并判断是否存在
        User user = userService.getByName(username);
        if(ObjectUtils.isEmpty(user)){
            return null;
        }
        //封装用户信息至对应的认证类中
        UserDetailsDTO userDetailsDTO = new UserDetailsDTO();
        userDetailsDTO.setUser(user);
        //TODO 获取角色对应的权限
        List<UserPermission> userPermissions = userPermissionService.list(new QueryWrapper<UserPermission>().eq("user_id", user.getUserId()));
        //TODO 获取权限id对应的所有权限
        List<String> pathList = new ArrayList<>();
        for (UserPermission userPermission : userPermissions) {
            List<Permission> permissionList = permissionService.list(new QueryWrapper<Permission>().eq("permission_id", userPermission.getPermissionId()));
            pathList.addAll(permissionList.stream().map(data-> data.getPermission()).collect(Collectors.toList()));
        }
        userDetailsDTO.setPermissionList(pathList);
        return userDetailsDTO;
    }

}
```

### 6.JwtUtil工具类说明

```java
/**
 * JWT工具类
 */
public class JwtUtil {

    //有效期为
    public static final Long JWT_TTL = 60 * 60 * 1000L;// 60 * 60 *1000  一个小时
    //设置秘钥明文
    public static final String JWT_KEY = "sangeng";

    public static String getUUID() {
        //随机生成token字符串
        String token = UUID.randomUUID().toString().replaceAll("-", "");
        return token;
    }

    /**
     * 生成jtw
     *
     * @param subject token中要存放的数据（json格式）
     * @return
     */
    public static String createJWT(String subject) {
        JwtBuilder builder = getJwtBuilder(subject, null, getUUID());// 设置过期时间
        return builder.compact();
    }

    /**
     * 生成jtw
     *
     * @param subject   token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return
     */
    public static String createJWT(String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID());// 设置过期时间
        return builder.compact();
    }

    private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid) {
        //签名的算法
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        //生成获取密钥
        SecretKey secretKey = generalKey();
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        if (ttlMillis == null) {
            ttlMillis = JwtUtil.JWT_TTL;
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
                .setId(uuid)              //唯一的ID
                .setSubject(subject)   // 主题  可以是JSON数据
                .setIssuer("sg")     // 签发者
                .setIssuedAt(now)      // 签发时间
                .signWith(signatureAlgorithm, secretKey) //使用HS256对称加密算法签名, 第二个参数为秘钥
                .setExpiration(expDate);//设置过期时间
    }

    /**
     * 创建token
     *
     * @param id
     * @param subject
     * @param ttlMillis
     * @return
     */
    public static String createJWT(String id, String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id);// 设置过期时间
        return builder.compact();
    }

    /**
     * 生成加密后的秘钥 secretKey
     *
     * @return
     */
    public static SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        return key;
    }

    /**
     * 解析
     *
     * @param jwt
     * @return
     * @throws Exception
     */
    public static Claims parseJWT(String jwt) throws Exception {
        SecretKey secretKey = generalKey();
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }
}
```

### 7.，创建过滤器JwtAuthenticationTokenFilter类拦截指定路径验证访问信息

**OncePerRequestFilter**：继承OncePerRequestFilter用于继承实现并在每次请求时只执行一次过滤

```java
package com.rfos.assistsilkworm.config.security;

import com.alibaba.fastjson.JSONObject;
import com.rfos.assistsilkworm.config.redis.RedisUtils;
import com.rfos.assistsilkworm.config.security.UserDetailsDTO;
import com.rfos.assistsilkworm.constant.CommonConstants;
import com.rfos.assistsilkworm.enums.ResultCode;
import com.rfos.assistsilkworm.exception.ApiException;
import com.rfos.assistsilkworm.util.IPAddrUtil;
import com.rfos.assistsilkworm.util.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;


/**
 * @date 2022/10/4
 */
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private RedisUtils redisUtil;
    //保证一次请求只调用一次doFilterInternal方法
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("用户访问requestURI={},ip={}", request.getRequestURI(), IPAddrUtil.getIpAddress(request));
        //获取请求头中的token
        String token = request.getHeader(CommonConstants.TOKEN_HEAD);
        //如果没有token则为第一次访问，过滤器放行-将请求转发给过滤器链上下一个对象
        if (!StringUtils.hasText(token)) {
            filterChain.doFilter(request, response);
            return;
        }
        //解析token
        log.info("获取到请求的token:\n"+token);
        String userId;
        try {
            Claims claims = JwtUtils.parseJWT(token);
            userId = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new ApiException(ResultCode.FAIL_AUTHORITY);
        }
        //从redis中获取用户信息
        Object obj = redisUtil.get(CommonConstants.TOKEN_HEAD + ":" + userId);
        if (Objects.isNull(obj)) {
            throw new ApiException(ResultCode.EMPTY_USER);
        }
        //获取认证对象的信息
        UserDetailsDTO userDetailsDTO = JSONObject.parseObject(obj.toString(), UserDetailsDTO.class);
        log.info("用户访问requestURI={},username={},ip={}", request.getRequestURI(), userDetailsDTO.getUsername(), IPAddrUtil.getIpAddress(request));
        //存入SecurityContextHolder
        //TODO 获取权限信息封装到Authentication中
        log.info("获取权限对应的所有权限:\n{}",userDetailsDTO.getAuthorities());
        /*
        UsernamePasswordAuthenticationToken继承AbstractAuthenticationToken实现Authentication
        所以当在页面中输入用户名和密码之后首先会进入到UsernamePasswordAuthenticationToken验证(Authentication)，
        然后生成的Authentication会被交由AuthenticationManager来进行管理
        而AuthenticationManager管理一系列的AuthenticationProvider，
        而每一个Provider都会通UserDetailsService和UserDetail来返回一个
        以UsernamePasswordAuthenticationToken实现的带用户名和密码以及权限的Authentication
        */
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userDetailsDTO, null, userDetailsDTO.getAuthorities());
        //将用户信息保存在安全上下文中
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        //放行
        filterChain.doFilter(request, response);
    }

}

```

### 8.创建自定义的UrlFilterInvocationSecurityMetadataSource类实现FilterInvocationSecurityMetadataSource接口

**FilterInvocationSecurityMetadataSource**：拦截url判断用户url的访问权限是否包含该用户的权限

```java
package com.rfos.assistsilkworm.config.security;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.rfos.assistsilkworm.pojo.Path;
import com.rfos.assistsilkworm.pojo.PermissionPath;
import com.rfos.assistsilkworm.service.PathService;
import com.rfos.assistsilkworm.service.PermissionPathService;
import com.rfos.assistsilkworm.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.security.access.SecurityConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * @author hjt
 * @Package com.kdcloud.srd.security
 * @date 2022/10/5 20:14
 * @description 获取url匹配的用户权限
 *
 */
@Component
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    //没有权限
    private static final String ROLE_NONE = "ROLE_NONE";
    @Autowired
    private PermissionPathService permissionPathService;
    @Autowired
    private PermissionService permissionService;
    @Autowired
    private PathService pathService;
    //路径匹配类
    AntPathMatcher antPathMatcher = new AntPathMatcher();

    //开放的路径
    private final static String[] OPEN_PATH_LIST = new String[]{
            "/**",
            "/static/**",
            "/templates/**",
            "/index","/login",
            "/admin/login",
            "/home/**",
            "/user/login",
            "/swagger-ui.html",
            "/swagger-resources/**",
            "/*/api-docs",
            "/webjars/**",
            "/v2/**",
            "/api/**",
            "/actuator/**"
    };
    //filterInvocation：获取该请求
    @Override
    public Collection<ConfigAttribute> getAttributes(Object requestObj) throws IllegalArgumentException {
        FilterInvocation filterInvocation = (FilterInvocation) requestObj;
        String requestUrl = filterInvocation.getRequestUrl();
        System.out.println("请求路径url："+requestUrl);
        //开放部分路径
        //静态资源不拦截
        if(isMatcherAllowedRequest(filterInvocation)){
            return null;
        }
        // 数据库中所有url
        List<Path> pathList = pathService.list();
        pathList.forEach(value-> System.out.println(value.getPath()));
        for (Path path : pathList) {
            // 获取该url所对应的权限
            boolean match = antPathMatcher.match(path.getPath(), requestUrl);
            System.out.println(match);
            if (match) {
                System.out.println("匹配的路径url\n："+path);
                //获取路径对应的所有权限
                List<PermissionPath> permissionPaths = permissionPathService.list(new QueryWrapper<PermissionPath>().eq("path_id", path.getPathId()));
                List<String> permissionPathList = new ArrayList<>();
                if (!CollectionUtils.isEmpty(permissionPaths)){
                    for (PermissionPath permissionPath : permissionPaths) {
                        String roleName = permissionService.getById(permissionPath.getPermissionId()).getPermission();
                        permissionPathList.add(roleName);
                    }
                }

                // 能访问url对应角色权限信息
                System.out.println("能访问url对应角色权限信息:"+permissionPathList);
                return SecurityConfig.createList(permissionPathList.stream().toArray(String[]::new));
            }
        }
        // 如果数据中没有找到相应url资源则为非法访问
        return  SecurityConfig.createList(ROLE_NONE);
    }

    /**
     * 判断当前请求是否在允许请求的范围内
     * @param fi 当前请求
     * @return 是否在范围中
     */
    private boolean isMatcherAllowedRequest(FilterInvocation fi){
        return allowedRequest().stream().map(AntPathRequestMatcher::new)
                .filter(requestMatcher -> requestMatcher.matches(fi.getHttpRequest()))
                .toArray().length > 0;
    }
    /**
     * @return 定义允许请求的列表
     */
    private List<String> allowedRequest(){
        return Arrays.asList(OPEN_PATH_LIST);
    }
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    /**
     * 表示返回的对象是否支持校验
     * @param aClass
     * @return
     */
    @Override
    public boolean supports(Class<?> aClass) {
        return FunctionalInterface.class.isAssignableFrom(aClass);
    }

}

```

### 9.决策访问处理器：创建自定义的JwtAccessDeniedManager实现AccessDeniedManager接口

```java
package com.rfos.assistsilkworm.config.security;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * @author hjt
 * @date 2022/10/5 23:29
 * @description决策访问处理器：创建自定义的JwtAccessDeniedManager实现AccessDeniedManager接口
 */
@Component
public class JwtAccessDeniedManager implements AccessDecisionManager {
    /**
     * auth：认证信息
     * collection：角色信息
     */
    @Override
    public void decide(Authentication auth, Object o, Collection<ConfigAttribute> collection) throws AccessDeniedException, InsufficientAuthenticationException {
        Collection<? extends GrantedAuthority> auths = auth.getAuthorities();
        for (ConfigAttribute configAttribute : collection) {
            if ("ROLE_LOGIN".equals(configAttribute.getAttribute())
                    && auth instanceof UsernamePasswordAuthenticationToken) {
                return;
            }
            for (GrantedAuthority authority : auths) {
                if (configAttribute.getAttribute().equals(authority.getAuthority())) {
                    return;
                }
            }
        }
        throw new AccessDeniedException("权限不足");
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}

```

## 10.创建Spring Security的配置类securityConfig

```java
package com.rfos.assistsilkworm.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;


@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) //开启注解匹配
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    //自动装配自定义逻辑
    @Autowired
    @Qualifier("userDetailsServiceImpl")
    private UserDetailsService userDetailsService;
    //过滤器JwtAuthenticationTokenFilter
    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
    //用户请求处理过程中遇到认证异常时，被ExceptionTranslationFilter用于开启特定认证方案(authentication schema)的认证流程
    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;
    //拒绝访问处理
    @Autowired
    private AccessDeniedHandler accessDeniedHandler;
    //决策处理器
    @Autowired
    private JwtAccessDeniedManager jwtAccessDeniedManager;
    //请求访问url处理过滤器
    @Autowired
    private UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource;

    //密码加密
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    //加密密码
    public static void main(String[] args) {
        SpringSecurityConfig springSecurityConfig = new SpringSecurityConfig();
        PasswordEncoder passwordEncoder = springSecurityConfig.passwordEncoder();
        String encode = passwordEncoder.encode("admin");
        System.out.println("加密后的密码:"+encode);

    }
    //配置访问路径


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //把token校验过滤器添加到过滤器链中
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        //请求需要经过权限认证
        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                //自定义的元数据源和权限决策配置
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O obj) {
                        obj.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource);
                        obj.setAccessDecisionManager(jwtAccessDeniedManager);
                        return obj;
                    }
                });
        //配置异常处理器 => 自定义的
        http.exceptionHandling()
                //配置认证失败处理器
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);
        //允许跨域
        http.cors();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //使用自己的UserDetailsService
        auth.userDetailsService(userDetailsService);
    }

}

```

### 11.创建登录接口，生成封装验证信息

```java
package com.rfos.assistsilkworm.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.rfos.assistsilkworm.common.CommonResult;
import com.rfos.assistsilkworm.dto.LoginDTO;
import com.rfos.assistsilkworm.pojo.User;

/**
 * <p>
 *  服务类
 * </p>
 *
 * @author rfos
 * @since 2022-11-02
 */
public interface UserService extends IService<User> {

    /**
     * 管理员登录验证
     * @param loginDTO
     * @return
     */
    CommonResult login(LoginDTO loginDTO);

    User getByName(String username);
}

```

```java
package com.rfos.assistsilkworm.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.github.pagehelper.util.StringUtil;
import com.rfos.assistsilkworm.common.CommonResult;
import com.rfos.assistsilkworm.config.redis.RedisUtils;
import com.rfos.assistsilkworm.config.security.UserDetailsDTO;
import com.rfos.assistsilkworm.constant.CommonConstants;
import com.rfos.assistsilkworm.constant.RedisConstants;
import com.rfos.assistsilkworm.dto.LoginDTO;
import com.rfos.assistsilkworm.enums.ResultCode;
import com.rfos.assistsilkworm.exception.ApiException;
import com.rfos.assistsilkworm.mapper.UserMapper;
import com.rfos.assistsilkworm.pojo.User;
import com.rfos.assistsilkworm.service.UserService;
import com.rfos.assistsilkworm.util.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

/**
 * <p>
 *  服务实现类
 * </p>
 *
 * @author rfos
 * @since 2022-11-02
 */
@Service
@Transactional(rollbackFor = Exception.class)
@Slf4j
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private RedisUtils redisUtils;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public CommonResult login(LoginDTO loginDTO) {
        //封装用户认证信息
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        if (Objects.isNull(authenticate)) {
            throw new ApiException("用户名或密码错误");
        }
        //使用username生成token令牌
        UserDetailsDTO userDetailsDTO = (UserDetailsDTO) authenticate.getPrincipal();
        String userId = String.valueOf(userDetailsDTO.getUser().getUserId());
        String jwt = JwtUtils.createJWT(userId);
        log.info("使用username生成token:\n"+jwt);
        //将认证信息authenticate存入redis
        log.info("authenticate存入redis:\n{}",userDetailsDTO);
        redisUtils.set(CommonConstants.TOKEN_HEAD +":"+ userId, JSONObject.toJSONString(userDetailsDTO));
        return CommonResult.success(jwt);
    }

    @Override
    public User getByName(String username) {
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        if(StringUtil.isNotEmpty(username)){
            userQueryWrapper.eq("username",username);
            userQueryWrapper.eq("is_del", CommonConstants.IS_NOT_DEL);
        }
        User user = userMapper.selectOne(userQueryWrapper);
        return user;
    }


}

```

## 12.效果展示-权限:ROLE_ADMIN ，权限对应的路径：/admin/**

**（1）登录接口**

请求信息：

![image-20221006133456383](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20221006133456383.png)

访问成功信息：

![image-20221006133554027](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20221006133554027.png)

验证失败信息

![image-20221006134604414](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20221006134604414.png)

**(2)其他接口**

鉴权成功：

![image-20221006134931755](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20221006134931755.png)

鉴权失败：

![image-20221006134657435](SpringSecurity%20+%20JWT-%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6.assets/image-20221006134657435.png)