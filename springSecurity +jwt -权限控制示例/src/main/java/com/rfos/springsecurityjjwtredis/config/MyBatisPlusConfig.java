package com.rfos.springsecurityjjwtredis.config;

import com.baomidou.mybatisplus.annotation.DbType;
import com.baomidou.mybatisplus.extension.plugins.MybatisPlusInterceptor;
import com.baomidou.mybatisplus.extension.plugins.inner.BlockAttackInnerInterceptor;
import com.baomidou.mybatisplus.extension.plugins.inner.PaginationInnerInterceptor;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import java.util.HashMap;

/**
 * @author zhouzc
 * @Package com.kdcloud.neiying.dao
 * @date 2020-11-24
 */
@Configuration
@MapperScan("springsecurityjjwtredis.mapper")
@EnableTransactionManagement
public class MyBatisPlusConfig{
    /**
     * 配置分页插件
     */
//    @Bean
//    public PaginationInterceptor paginationInterceptor(){
//        return new PaginationInterceptor();
//    }

    /**
     * 直接添加-MybatisPlusInterceptor配置拦截器插件
     * 注意版本问题，低版本没有-3.4.2
     * @return
     */
    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        //定义MP拦截器
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        //添加具体的拦截器
        //分页插件-MySQL
        interceptor.addInnerInterceptor(new PaginationInnerInterceptor(DbType.MYSQL));
        //防止全表更新插件
        interceptor.addInnerInterceptor(new BlockAttackInnerInterceptor());
        return interceptor;
    }

}
