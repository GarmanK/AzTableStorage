<#
 .SYNOPSIS
  Displays connects to Azure Table Storage and interacts with data.

 .DESCRIPTION
  Connects to Azure Table Storage and interacts with data. This module provides functions to authenticate, retrieve, insert, and update rows in Azure Table Storage.

 .EXAMPLE
    Authenticate to Azure Table Storage using Enterprise Application.
   Connect-AzTableStorage -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"

 .EXAMPLE
   Get content from a specific table in Azure Table Storage.
   $content = Get-AzTableStorageTableContent -AccountName "your-account-name" -TableName "your-table-name"

 .EXAMPLE
   Add a new row into a table in Azure Table Storage.
   Add-AzTableStorageRow -AccountName "your-account-name" -TableName "your-table-name" -PartitionKey "your-partition-key" -RowKey "your-row-key" -Properties @{"Property1"="Value1"; "Property2"="Value2"}
   
 .EXAMPLE
   Update a new row into a table in Azure Table Storage. This uses the rest API merge method.
    Merge-AzTableStorageRow -AccountName "your-account-name" -TableName "your-table-name" -PartitionKey "your-partition-key" -RowKey "your-row-key" -Properties @{"Property1"="Value1"; "Property2"="Value2"}

 .EXAMPLE
    Get rows from a table in Azure Table Storage.
    $rows = Get-AzTableStorageRows -AccountName "your-account-name" -TableName "your-table-name" -PartitionKey "your-partition-key" -RowKey "your-row-key"
    
 .EXAMPLE
    Set Context of command, Storage Account and Table Name
    $Context = New-AzTableStorageContext -StorageAccountName "your-account-name" -StorageAccountKey "your-storage-account-key"
#>

#Region Auth
function Connect-AzTableStorage {
    param (
        [Parameter(Mandatory = $false)][string]$Token,
        [Parameter(Mandatory = $false)][string]$TokenExpiration,
        [Parameter(Mandatory = $false)][string]$TenantId,
        [Parameter(Mandatory = $false)][string]$ClientId,
        [Parameter(Mandatory = $false)][string]$ClientSecret,
        [string]$Resource = "https://storage.azure.com/"
    )

    $global:AzTableStoragetokenResponse = $null
    
    if (!$Token) {
        if (!$TenantId -or !$ClientId -or !$ClientSecret) {
            throw "When using -UseEnterpriseApp, please provide TenantId, ClientId, and ClientSecret."
        }
        $global:AzTableStorageAuthDetials = @{
            TenantId     = $TenantId
            ClientId     = $ClientId
            ClientSecret = $ClientSecret
        }
    
        # Acquire a token using the enterprise application's credentials
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            resource      = $Resource
        }
    
        $global:AzTableStoragetokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" -Body $body -ContentType "application/x-www-form-urlencoded"
    
        if ($AzTableStoragetokenResponse -and $AzTableStoragetokenResponse.access_token) {
            Write-Host "Successfully authenticated to Azure Table Storage."
            return
        } else {
            throw "Failed to authenticate to Azure Table Storage."
        }
    }elseif ($Token) {
        $global:AzTableStoragetokenResponse = [pscustomobject]@{
            access_token = $Token
            expires_on   = $TokenExpiration
        }
        Write-Host "Using provided token for Azure Table Storage."
        return
    }else {
        throw "Please provide a valid token or provide valid Enterprise App Credentials."
    }

}



#Region Check Token Expiration
function Test-AzTableStorageTokenExpiration {
    #set time vars
    [long]$expiresOn = $global:AzTableStoragetokenResponse.expires_on
    [long]$now       = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    if ($global:AzTableStoragetokenResponse -and $global:AzTableStorageAuthDetials) {
        if ($now -gt $expiresOn) {
            Write-Host "Token expired. Re-authenticating..."
            Connect-AzTableStorage @AzTableStorageAuthDetials
        }
    return
    }elseif ($global:AzTableStoragetokenResponse -and !$global:AzTableStorageAuthDetials) {
        # Check if the token is expired
        if ($now -gt $expiresOn) {
            return 403
        } else {
            return
        }
    }
    else {
        Throw
    }
}

#region new Context
function New-AzTableStorageContext {
    param (
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$TableName
    )

    $context = @{
        AccountName = $AccountName
        TableName  = $TableName
    }
    return $context
}

#region Add Row
function Add-AzTableStorageRow {
    param (
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey,
        [Parameter(Mandatory = $true)][string]$RowKey,
        [hashtable]$Properties
    )
    # Check if the token is expired and re-authenticate if necessary
    $testresponse = Test-AzTableStorageTokenExpiration
    if ($testresponse -eq 403) {
        Write-Error "Token expired. Please re-authenticate."
        Throw 403
    }
    # If the token is valid, proceed with the request
    try {
        $bearerToken = $global:AzTableStoragetokenResponse.access_token
        $uri         = "https://$AccountName.table.core.windows.net/$TableName"
        $headers     = @{
            "Authorization"        = "Bearer $bearerToken"
            "x-ms-version"         = "2025-05-05"
            "Accept"               = "application/json;odata=nometadata"
            "Content-Type"         = "application/json"
            "DataServiceVersion"   = "3.0"
            "MaxDataServiceVersion"= "3.0"
            "Prefer"               = "return-no-content"
            'x-ms-date'     = [DateTime]::UtcNow.ToString('R')
        }

        $body = @{
            "PartitionKey" = $PartitionKey
            "RowKey"       = $RowKey
        }

        foreach ($key in $Properties.Keys) {
            $body[$key] = $Properties[$key]
        }

        $jsonBody = $body | ConvertTo-Json
        $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $jsonBody

        return $response
    } catch {
        Write-Error "Failed to add row into table storage"
        throw
    }
}

#region Merge Row
function Merge-AzTableStorageRow {
    param (
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey,
        [Parameter(Mandatory = $true)][string]$RowKey,
        [Parameter(Mandatory = $true)][hashtable]$Properties
    )
    # Check if the token is expired and re-authenticate if necessary
    $testresponse = Test-AzTableStorageTokenExpiration
    if ($testresponse -eq 403) {
        Write-Error "Token expired. Please re-authenticate."
        Throw 403
    }
    # If the token is valid, proceed with the request
    try {
        $bearerToken = $global:AzTableStoragetokenResponse.access_token
        $uri         = "https://$AccountName.table.core.windows.net/$TableName(PartitionKey='$PartitionKey',RowKey='$RowKey')"
        $headers     = @{
            "Authorization"        = "Bearer $bearerToken"
            "x-ms-version"         = "2025-05-05"
            "Accept"               = "application/json;odata=nometadata"
            "Content-Type"         = "application/json"
            "DataServiceVersion"   = "3.0"
            "MaxDataServiceVersion"= "3.0"
            'x-ms-date'     = [DateTime]::UtcNow.ToString('R')
        }

        $body = @{
            "PartitionKey" = $PartitionKey
            "RowKey"       = $RowKey
        }

        foreach ($key in $Properties.Keys) {
            $body[$key] = $Properties[$key]
        }

        $jsonBody = $body | ConvertTo-Json
        $response = Invoke-RestMethod -Uri $uri -Method MERGE -Headers $headers -Body $jsonBody
        return $response
    }
    catch {
        Write-Error "Failed to merge row into table storage:"
        throw
    }
}

#region Get-AzTableStorageRows
function Get-AzTableStorageRows {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [string]$PartitionKey,
        [string]$RowKey
    )
    # Check if the token is expired and re-authenticate if necessary
    $testresponse = Test-AzTableStorageTokenExpiration
    if ($testresponse -eq 403) {
        Write-Error "Token expired. Please re-authenticate."
        Throw 403
    }
    # If the token is valid, proceed with the request
    try {
        $bearerToken = $global:AzTableStoragetokenResponse.access_token
        if ($RowKey -and $PartitionKey) {
            $uri = "https://$AccountName.table.core.windows.net/$TableName(PartitionKey='$PartitionKey',RowKey='$RowKey')"
        } elseif (!$RowKey -and $PartitionKey) {
            $uri = "https://$AccountName.table.core.windows.net/$TableName()?`$filter=PartitionKey eq '$PartitionKey'"
        } elseif ($RowKey -and !$PartitionKey) {
            $uri = "https://$AccountName.table.core.windows.net/$TableName()?`$filter=RowKey eq '$RowKey'"
        } elseif (!$RowKey -and !$PartitionKey) {
            $uri = "https://$AccountName.table.core.windows.net/$TableName"
        }

        $headers = @{
            "Authorization" = "Bearer $bearerToken"
            "x-ms-version"  = "2025-05-05"
            "Accept"        = "application/json;odata=nometadata"
            'x-ms-date'     = [DateTime]::UtcNow.ToString('R')
        }

        $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        if ($RowKey -and $PartitionKey) {
            if ($response -and $response.PartitionKey -eq $PartitionKey -and $response.RowKey -eq $RowKey) {
                return $response
            }
            else {
                Write-Host "No matching row found."
                return $null
            }
        }
        else {
            if (!$response.value) {
                Write-Host "No rows found."
                return $null
            }
            else {
                return $response.value
            }
        }
    }
    catch {
        write-error "Failed to retrieve row from table storage"
        throw
    }
}

#region Remove Row
function Remove-AzTableStorageRow {
    param(
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey,
        [Parameter(Mandatory = $true)][string]$RowKey
    )
    # Check if the token is expired and re-authenticate if necessary
    $testresponse = Test-AzTableStorageTokenExpiration
    if ($testresponse -eq 403) {
        Write-Error "Token expired. Please re-authenticate."
        Throw 403
    }
    # If the token is valid, proceed with the request
    try {
        $bearerToken = $global:AzTableStoragetokenResponse.access_token
        $uri         = "https://$AccountName.table.core.windows.net/$TableName(PartitionKey='$PartitionKey',RowKey='$RowKey')"
        $headers     = @{
            "Authorization" = "Bearer $bearerToken"
            "x-ms-version"  = "2025-05-05"
            "Accept"        = "application/json;odata=nometadata"
            "If-Match"      = "*"
            'x-ms-date'     = [DateTime]::UtcNow.ToString('R')
        }

        Invoke-RestMethod -Uri $uri -Method DELETE -Headers $headers
        Write-Host "Row successfully deleted."
    }
    catch {
        Write-Error "Failed to delete row from table storage"
        throw
    }
}

#Region Export Functions to Module
Export-ModuleMember -Function Connect-AzTableStorage, Add-AzTableStorageRow, Merge-AzTableStorageRow, Get-AzTableStorageRows, New-AzTableStorageContext, Remove-AzTableStorageRow