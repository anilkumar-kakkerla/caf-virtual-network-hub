# This is a consolidated main.tf file.
# You will also need:
# 1. A 'versions.tf' (or similar) containing your terraform {} and required_providers {} blocks.
# 2. A 'variables.tf' defining all 'var.' used here.
# 3. An 'outputs.tf' to expose relevant resource attributes.
# 4. A 'provider.tf' (or in main.tf) with 'provider "azurerm" { ... }' configuration.

#---------------------------------
# Local declarations
#---------------------------------
locals {
  # Dynamically determine resource group name and location,
  # allowing for creation or selection of an existing one.
  resource_group_name = element(coalescelist(data.azurerm_resource_group.rgrp.*.name, azurerm_resource_group.rg.*.name, [""]), 0)
  location            = element(coalescelist(data.azurerm_resource_group.rgrp.*.location, azurerm_resource_group.rg.*.location, [""]), 0)

  # Conditional list for DDoS protection plan dynamic block
  if_ddos_enabled = var.create_ddos_plan ? [{}] : []

  # Map public IP names for easier iteration and lookup
  public_ip_map = { for pip in var.public_ip_names : pip => true }

  # Transform Firewall rule lists into maps keyed by rule name for iteration
  fw_nat_rules = { for idx, rule in var.firewall_nat_rules : rule.name => {
    idx  = idx
    rule = rule
    }
  }

  fw_network_rules = { for idx, rule in var.firewall_network_rules : rule.name => {
    idx  = idx
    rule = rule
    }
  }

  fw_application_rules = { for idx, rule in var.firewall_application_rules : rule.name => {
    idx  = idx
    rule = rule
    }
  }
}


#---------------------------------------------------------
# Resource Group Creation or selection
#----------------------------------------------------------
# Data source to lookup an existing Resource Group if `create_resource_group` is false
# Data source to lookup an existing Resource Group if `create_resource_group` is false
data "azurerm_resource_group" "rgrp" {
  count = var.create_resource_group == false ? 1 : 0
  name  = var.resource_group_name
}

# Resource to create a new Resource Group if `create_resource_group` is true
resource "azurerm_resource_group" "rg" {
  count = var.create_resource_group ? 1 : 0

  name     = var.create_resource_group ? lower(var.resource_group_name) : "dummy-rg"
  location = var.create_resource_group ? var.location : "eastus"  # dummy fallback
  tags     = var.create_resource_group ? merge({ "ResourceName" = var.resource_group_name }, var.tags) : {}
}



#-------------------------------------
# VNET Creation
#-------------------------------------
resource "azurerm_virtual_network" "vnet" {
  name                = lower("vnet-${var.hub_vnet_name}-${local.location}")
  location            = local.location
  resource_group_name = local.resource_group_name
  address_space       = var.vnet_address_space
  dns_servers         = var.dns_servers # Keep if var.dns_servers is provided and relevant for your architecture
  tags                = merge({ "ResourceName" = lower("vnet-${var.hub_vnet_name}-${local.location}") }, var.tags)

  # Attach DDoS Protection Plan if enabled
  dynamic "ddos_protection_plan" {
    for_each = local.if_ddos_enabled

    content {
      id     = azurerm_network_ddos_protection_plan.ddos[0].id
      enable = true
    }
  }
}

#--------------------------------------------
# DDoS Protection Plan
#--------------------------------------------
resource "azurerm_network_ddos_protection_plan" "ddos" {
  count               = var.create_ddos_plan ? 1 : 0
  name                = lower("${var.hub_vnet_name}-ddos-protection-plan")
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "ResourceName" = lower("${var.hub_vnet_name}-ddos-protection-plan") }, var.tags)
}


#-------------------------------------
# Network Watcher
#-------------------------------------
# Resource Group for Network Watcher (often "NetworkWatcherRG" in each region)
resource "azurerm_resource_group" "nwatcher" {
  count    = var.create_network_watcher ? 1 : 0 # Simplified condition
  name     = "NetworkWatcherRG"
  location = local.location
  tags     = merge({ "ResourceName" = "NetworkWatcherRG" }, var.tags)
}

# Network Watcher instance
resource "azurerm_network_watcher" "nwatcher" {
  count               = var.create_network_watcher ? 1 : 0 # Simplified condition
  name                = "NetworkWatcher_${local.location}"
  location            = local.location
  resource_group_name = azurerm_resource_group.nwatcher[0].name
  tags                = merge({ "ResourceName" = format("%s", "NetworkWatcher_${local.location}") }, var.tags)
}


#--------------------------------------------------------------------------------------------------------
# Subnets Creation (Firewall, Gateway, and General Purpose)
# Includes private link endpoint/service network policies, service endpoints, and Delegation.
#--------------------------------------------------------------------------------------------------------
resource "azurerm_subnet" "fw-snet" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.firewall_subnet_address_prefix
  service_endpoints    = var.firewall_service_endpoints
}

resource "azurerm_subnet" "gw_snet" {
  count                = var.gateway_subnet_address_prefix != null ? 1 : 0
  name                 = "GatewaySubnet"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.gateway_subnet_address_prefix
  service_endpoints    = var.gateway_service_endpoints
}

resource "azurerm_subnet" "snet" {
  for_each             = var.subnets
  name                 = lower(format("snet-%s-${var.hub_vnet_name}-${local.location}", each.value.subnet_name))
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = each.value.subnet_address_prefix
  service_endpoints    = lookup(each.value, "service_endpoints", [])

  # These policies are supported with AzureRM Provider >= 2.72.0.
  # As you're using >= 4.0.0, they are supported.
  # They are conditional based on your 'var.subnets' input, defaulting to null.
  #private_endpoint_network_policies_enabled     = lookup(each.value, "private_endpoint_network_policies_enabled", null)
  #private_link_service_network_policies_enabled = lookup(each.value, "private_link_service_network_policies_enabled", null)

  # Dynamically add subnet delegation if specified in var.subnets
  dynamic "delegation" {
    for_each = lookup(each.value, "delegation", {}) != {} ? [1] : []
    content {
      name = lookup(each.value.delegation, "name", null)
      service_delegation {
        name    = lookup(each.value.delegation.service_delegation, "name", null)
        actions = lookup(each.value.delegation.service_delegation, "actions", null)
      }
    }
  }
}


#---------------------------------------------------------------
# Network Security Groups (NSG) created for every custom subnet
#---------------------------------------------------------------
resource "azurerm_network_security_group" "nsg" {
  for_each            = var.subnets
  name                = lower("nsg_${each.key}_in") # Consider if "_in" is always appropriate for the NSG name
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "ResourceName" = lower("nsg_${each.key}_in") }, var.tags)

  dynamic "security_rule" {
    # WARNING: This uses positional array indexing (security_rule.value[0], etc.)
    # which is fragile. It's highly recommended to refactor your 'var.subnets'
    # to use named attributes for NSG rules (e.g., 'rule.name', 'rule.priority').
    for_each = concat(lookup(each.value, "nsg_inbound_rules", []), lookup(each.value, "nsg_outbound_rules", []))
    content {
      name                       = security_rule.value[0] == "" ? "Default_Rule" : security_rule.value[0]
      priority                   = security_rule.value[1]
      direction                  = security_rule.value[2] == "" ? "Inbound" : security_rule.value[2]
      access                     = security_rule.value[3] == "" ? "Allow" : security_rule.value[3]
      protocol                   = security_rule.value[4] == "" ? "Tcp" : security_rule.value[4]
      source_port_range          = "*" # Hardcoded. If variable source ports are needed, this should be configurable.
      destination_port_range     = security_rule.value[5] == "" ? "*" : security_rule.value[5]
      source_address_prefix      = security_rule.value[6] == "" ? element(each.value.subnet_address_prefix, 0) : security_rule.value[6]
      destination_address_prefix = security_rule.value[7] == "" ? element(each.value.subnet_address_prefix, 0) : security_rule.value[7]
      description                = "${security_rule.value[2]}_Port_${security_rule.value[5]}"
    }
  }
}

# Associate NSG with corresponding subnet
resource "azurerm_subnet_network_security_group_association" "nsg-assoc" {
  for_each                  = var.subnets
  subnet_id                 = azurerm_subnet.snet[each.key].id
  network_security_group_id = azurerm_network_security_group.nsg[each.key].id
}



#-------------------------------------------------
# Route Table to divert traffic through Firewall
#-------------------------------------------------
resource "azurerm_route_table" "rtout" {
  name                = "route-network-outbound"
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "ResourceName" = "route-network-outbound" }, var.tags)
}

# Associate route table with custom subnets
resource "azurerm_subnet_route_table_association" "rtassoc" {
  for_each       = var.subnets
  subnet_id      = azurerm_subnet.snet[each.key].id
  route_table_id = azurerm_route_table.rtout.id
}

# Default route to the Azure Firewall for outbound traffic
resource "azurerm_route" "rt" {
  name                  = lower("route-to-firewall-${var.hub_vnet_name}-${local.location}")
  resource_group_name   = local.resource_group_name # Changed from var.resource_group_name for consistency
  route_table_name      = azurerm_route_table.rtout.name
  address_prefix        = "0.0.0.0/0"
  next_hop_type         = "VirtualAppliance"
  next_hop_in_ip_address = azurerm_firewall.fw.ip_configuration[0].private_ip_address # Assumes at least one IP config
}



#----------------------------------------
# Private DNS Zone
#----------------------------------------
resource "azurerm_private_dns_zone" "dz" {
  count               = var.private_dns_zone_name != null ? 1 : 0
  name                = var.private_dns_zone_name
  resource_group_name = local.resource_group_name
  tags                = merge({ "ResourceName" = format("%s", lower(var.private_dns_zone_name)) }, var.tags)
}

resource "azurerm_private_dns_zone_virtual_network_link" "dzvlink" {
  count               = var.private_dns_zone_name != null ? 1 : 0
  name                = lower("${var.private_dns_zone_name}-link")
  resource_group_name = local.resource_group_name
  virtual_network_id  = azurerm_virtual_network.vnet.id
  private_dns_zone_name = azurerm_private_dns_zone.dz[0].name
  tags                = merge({ "ResourceName" = format("%s", lower("${var.private_dns_zone_name}-link")) }, var.tags)
}



#----------------------------------------------------------------
# Azure Role Assignment for Service Principal - current user
# (For VNet Peering and Private DNS Zone management)
#-----------------------------------------------------------------
data "azurerm_client_config" "current" {}

resource "azurerm_role_assignment" "peering" {
  scope                = azurerm_virtual_network.vnet.id
  role_definition_name = "Network Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "dns" {
  # This role assignment only happens if azurerm_private_dns_zone.dz is created
  count                = var.private_dns_zone_name != null ? 1 : 0
  scope                = azurerm_private_dns_zone.dz[0].id
  role_definition_name = "Private DNS Zone Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}



#------------------------------------------
# Public IP resources for Azure Firewall
#------------------------------------------
# Random string for unique domain name labels
resource "random_string" "str" {
  for_each = local.public_ip_map
  length   = 6
  special  = false
  upper    = false
  keepers = {
    domain_name_label = each.key
  }
}

# Public IP Prefix for Firewall (if needed)
resource "azurerm_public_ip_prefix" "pip_prefix" {
  name                = lower("${var.hub_vnet_name}-pip-prefix")
  location            = local.location
  resource_group_name = local.resource_group_name
  prefix_length       = 30 # A /30 prefix provides 2 usable IPs for Firewall
  tags                = merge({ "ResourceName" = lower("${var.hub_vnet_name}-pip-prefix") }, var.tags)
}

# Public IPs for Azure Firewall
resource "azurerm_public_ip" "fw-pip" {
  for_each            = local.public_ip_map
  name                = lower("pip-${var.hub_vnet_name}-${each.key}-${local.location}")
  location            = local.location
  resource_group_name = local.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  public_ip_prefix_id = azurerm_public_ip_prefix.pip_prefix.id # Associate with prefix
  domain_name_label   = format("%s%s", lower(replace(each.key, "/[[:^alnum:]]/", "")), random_string.str[each.key].result)
  tags                = merge({ "ResourceName" = lower("pip-${var.hub_vnet_name}-${each.key}-${local.location}") }, var.tags)
}

#-----------------
# Azure Firewall
#-----------------
resource "azurerm_firewall" "fw" {
  name                = lower("fw-${var.hub_vnet_name}-${local.location}")
  location            = local.location
  resource_group_name = local.resource_group_name
  sku_name            = var.sku_name
  sku_tier            = var.sku_tier
  zones               = var.firewall_zones # Optional: specify availability zones for firewall
  tags                = merge({ "ResourceName" = lower("fw-${var.hub_vnet_name}-${local.location}") }, var.tags)

  dynamic "ip_configuration" {
    for_each = local.public_ip_map
    iterator = ip
    content {
      name               = ip.key
      # Assign the Firewall subnet only to the first IP configuration
      subnet_id          = ip.key == var.public_ip_names[0] ? azurerm_subnet.fw-snet.id : null
      public_ip_address_id = azurerm_public_ip.fw-pip[ip.key].id
    }
  }
}



#----------------------------------------------
# Azure Firewall Network/Application/NAT Rules
#----------------------------------------------
resource "azurerm_firewall_application_rule_collection" "fw_app" {
  for_each            = local.fw_application_rules
  name                = lower(format("fw-app-rule-%s-${var.hub_vnet_name}-${local.location}", each.key))
  azure_firewall_name = azurerm_firewall.fw.name
  resource_group_name = local.resource_group_name
  priority            = 100 * (each.value.idx + 1)
  action              = each.value.rule.action

  rule {
    name           = each.key
    source_addresses = each.value.rule.source_addresses
    target_fqdns   = each.value.rule.target_fqdns

    protocol {
      type = each.value.rule.protocol.type
      port = each.value.rule.protocol.port
    }
  }
}

resource "azurerm_firewall_network_rule_collection" "fw_net" { # Renamed to fw_net to avoid conflict with azurerm_firewall_nat_rule_collection "fw"
  for_each            = local.fw_network_rules
  name                = lower(format("fw-net-rule-%s-${var.hub_vnet_name}-${local.location}", each.key))
  azure_firewall_name = azurerm_firewall.fw.name
  resource_group_name = local.resource_group_name
  priority            = 100 * (each.value.idx + 1)
  action              = each.value.rule.action

  rule {
    name                = each.key
    source_addresses    = each.value.rule.source_addresses
    destination_ports   = each.value.rule.destination_ports
    destination_addresses = [for dest in each.value.rule.destination_addresses : contains(var.public_ip_names, dest) ? azurerm_public_ip.fw-pip[dest].ip_address : dest]
    protocols           = each.value.rule.protocols
  }
}

resource "azurerm_firewall_nat_rule_collection" "fw_nat" { # Renamed to fw_nat to avoid conflict with azurerm_firewall_network_rule_collection "fw"
  for_each            = local.fw_nat_rules
  name                = lower(format("fw-nat-rule-%s-${var.hub_vnet_name}-${local.location}", each.key))
  azure_firewall_name = azurerm_firewall.fw.name
  resource_group_name = local.resource_group_name
  priority            = 100 * (each.value.idx + 1)
  action              = each.value.rule.action

  rule {
    name                = each.key
    source_addresses    = each.value.rule.source_addresses
    destination_ports   = each.value.rule.destination_ports
    destination_addresses = [for dest in each.value.rule.destination_addresses : contains(var.public_ip_names, dest) ? azurerm_public_ip.fw-pip[dest].ip_address : dest]
    protocols           = each.value.rule.protocols
    translated_address  = each.value.rule.translated_address
    translated_port     = each.value.rule.translated_port
  }
}


#-----------------------------------------------
# Storage Account for Logs Archive
#-----------------------------------------------
resource "azurerm_storage_account" "storeacc" {
  name                        = format("stdiaglogs%s", lower(replace("${random_string.main.result}", "/[[:^alnum:]]/", "")))
  resource_group_name         = local.resource_group_name
  location                    = local.location
  account_kind                = "StorageV2"
  account_tier                = "Standard"
  account_replication_type    = "GRS" # Geo-Redundant Storage
  #enable_https_traffic_only   = true
  tags                        = merge({ "ResourceName" = format("stdiaglogs%s", lower(replace(var.hub_vnet_name, "/[[:^alnum:]]/", ""))) }, var.tags)
}


#-----------------------------------------------
# Log Analytics Workspace for Logs Analysis
#-----------------------------------------------
resource "random_string" "main" {
  length  = 8
  special = false
  keepers = {
    name = var.hub_vnet_name
  }
}

resource "azurerm_log_analytics_workspace" "logws" {
  name                = lower("logaws-${random_string.main.result}-${var.hub_vnet_name}-${local.location}")
  resource_group_name = local.resource_group_name
  location            = local.location
  sku                 = var.log_analytics_workspace_sku
  retention_in_days   = var.log_analytics_logs_retention_in_days
  tags                = merge({ "ResourceName" = lower("logaws-${random_string.main.result}-${var.hub_vnet_name}-${local.location}") }, var.tags)
}



#-----------------------------------------
# Network Flow Logs for subnet and NSG
#-----------------------------------------
resource "azurerm_network_watcher_flow_log" "nwflog" {
  for_each            = var.subnets
  # ENSURE UNIQUE NAME PER FLOW LOG - Added each.key
  name                = lower("${azurerm_network_watcher.nwatcher[0].name}-flow-log-${each.key}")
  network_watcher_name = azurerm_network_watcher.nwatcher[0].name
  resource_group_name = azurerm_resource_group.nwatcher[0].name
  network_security_group_id = azurerm_network_security_group.nsg[each.key].id
  storage_account_id  = azurerm_storage_account.storeacc.id
  enabled             = true
  version             = 2
  retention_policy {
    enabled = true
    # Setting days to 0 means logs are immediately deleted from storage after being processed by Traffic Analytics.
    # If you want to keep raw logs in storage, set this to a positive number (e.g., 90 for 90 days).
    days    = 0
  }

  traffic_analytics {
    enabled             = true
    workspace_id        = azurerm_log_analytics_workspace.logws.workspace_id
    workspace_region    = local.location # Using local.location for consistency
    workspace_resource_id = azurerm_log_analytics_workspace.logws.id
    interval_in_minutes = 10
  }
}



#---------------------------------------------------------------
# Azure Monitoring Diagnostics - VNet, NSG, PIP, and Firewall
# (Sending logs and metrics to Storage Account and Log Analytics)
#---------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "vnet" {
  name                       = lower("vnet-${var.hub_vnet_name}-diag")
  target_resource_id         = azurerm_virtual_network.vnet.id
  storage_account_id         = azurerm_storage_account.storeacc.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logws.id

  # It's common for VNet to only export "VMProtectionAlerts" as other network logs
  # are typically captured at NSG/Flow Log level.
  #log {
   # category = "VMProtectionAlerts"
    #enabled  = true
    #retention_policy {
      #enabled = false # Retention managed by Log Analytics Workspace or storage account itself
    #}
  #}
  metric {
    category = "AllMetrics"
    #retention_policy {
      enabled = false # Retention managed by Log Analytics Workspace
    #}
  }
}

resource "azurerm_monitor_diagnostic_setting" "nsg" {
  for_each                   = var.subnets
  name                       = lower("${each.key}-diag")
  target_resource_id         = azurerm_network_security_group.nsg[each.key].id
  storage_account_id         = azurerm_storage_account.storeacc.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logws.id

  #dynamic "log" {
    #for_each = var.nsg_diag_logs # Variable should define which NSG log categories to enable
    #content {
      #category = log.value
      #enabled  = true
      #retention_policy {
        #enabled = false
      #}
    #}
  #}

  # NSG metrics are typically useful as well
  metric {
    category = "AllMetrics"
    retention_policy {
      enabled = false
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "fw-diag" {
  name                       = lower("fw-${var.hub_vnet_name}-diag")
  target_resource_id         = azurerm_firewall.fw.id
  storage_account_id         = azurerm_storage_account.storeacc.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logws.id

  #dynamic "log" {
    #for_each = var.fw_diag_logs # Variable should define which Firewall log categories to enable
    #content {
      #category = log.value
      #enabled  = true
      #retention_policy {
        #enabled = false
      #}
    #}
  #}

  metric {
    category = "AllMetrics"
    retention_policy {
      enabled = false
    }
  }
}