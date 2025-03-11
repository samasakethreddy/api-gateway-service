package com.saketh.pg_api_gateway.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Tenant {

	private String ownerId;

	private String tenantName;

	private int tenantAge;

	private int roomId;

	private String aadharId;

	private String email;

	private String phoneNumber;

	private LocalDate joinDate;
}
