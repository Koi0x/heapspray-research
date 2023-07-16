# Writing Windows kernel-mode registry filters
This excerpt will delve into the subject of crafting a fundamental registry filter kernel driver for Windows. The primary objective of this registry filter is to safeguard designated registry keys against unauthorized viewing or modification. Such a capability is useful for protecting essential registry artifacts like Anti-Virus/EDR components, while also serving as a potent tool for red-team engagements by thwarting malicious registry artifacts such as implant services.

### Understanding Registry Filters
A registry filtering driver refers to a kernel-mode driver that performs filtering on registry calls. By leveraging the configuration manager, which handles registry operations, registry filtering drivers gain the ability to filter registry function calls made by any thread.

To enable notification handling, registry filter drivers need to register a `RegistryCallback` routine using the CmRegisterCallbackEx function. Once successfully registered, the `RegistryCallback` routine will receive a pointer to a REG_XXX_KEY_INFORMATION structure, which provides detailed information about the ongoing registry operation.

*Registering a RegistryCallback routine*
```
NTSTATUS RET102_REGISTER_SERVICE_CALLBACK(
	PDRIVER_OBJECT DriverObject
)
{
	UNICODE_STRING RET102_REGISTRY_CALLBACK_ALTITUDE = RTL_CONSTANT_STRING(L"360000");
	NTSTATUS RET102_REGISTRY_CALLBACK_STATUS = CmRegisterCallbackEx(RET102_SERVICE_REG_CALLBACK, &RET102_REGISTRY_CALLBACK_ALTITUDE, DriverObject, NULL, &RET102_REG_CB_COOKIE, NULL);

	if (!NT_SUCCESS(RET102_REGISTRY_CALLBACK_STATUS))
	{
		return RET102_REGISTRY_CALLBACK_STATUS;
	}
	
	return RET102_REGISTRY_CALLBACK_STATUS;
}

```

Once your driver has successfully registered a `RegistryCallback` routine, the configuration manager will invoke this routine whenever a thread initiates a registry operation. These threads can originate from user-mode applications utilizing user-mode registry routines (such as RegCreateKeyEx, RegOpenKeyEx, etc.) or from drivers using kernel-mode registry routines (such as ZwCreateKey, ZwOpenKey, etc..).

### Handling Notifications
As mentioned above, the `RegistryCallback` routine is passed a pointer to a REG_XXX_KEY_INFORMATION structure, which holds pertinent details about the ongoing registry operation. This structure provides valuable information regarding the nature of the registry operation taking place.

### Blocking Registry Calls
By returning a non-success NTSTATUS value from its `RegistryCallback` routine, a registry filtering driver can effectively block registry operations. If the returned status value does not satisfy the condition NT_SUCCESS(status) (meaning it evaluates to FALSE), the configuration manager promptly terminates the operation and returns the specified status value to the calling thread. This allows the registry filtering driver to utilize pre-notifications as a means to prevent the processing of registry operations.

The provided code snippet employs a mechanism where, upon identifying the specified registry key, it will consistently return `STATUS_ACCESS_DENIED` for any operation involving that key. This effectively restricts any attempt to view or modify the contents of the registry key, ensuring its protection.

```
LARGE_INTEGER RET102_REG_CB_COOKIE = {0};

NTSTATUS RET102_SERVICE_REG_CALLBACK(
	IN PVOID CallbackContext,
	IN PVOID Argument1,
	IN PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	REG_NOTIFY_CLASS RET102_SERVICE_REGISTRY_CALLBACK_OPERATION = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	switch (RET102_SERVICE_REGISTRY_CALLBACK_OPERATION)
	{
	case RegNtPreOpenKeyEx:
	{
		PREG_OPEN_KEY_INFORMATION RET102_SERVICE_REGISTRY_CB_INFO = (PREG_OPEN_KEY_INFORMATION)Argument2;
		if (RET102_SERVICE_REGISTRY_CB_INFO != NULL && RET102_SERVICE_REGISTRY_CB_INFO->CompleteName != NULL)
		{
			UNICODE_STRING RET102_SERVICE_REGISTRY_KEY_PROT_NAME;
			RtlInitUnicodeString(&RET102_SERVICE_REGISTRY_KEY_PROT_NAME, L"SYSTEM\\CurrentControlSet\\Services\\RET");

			if (RtlEqualUnicodeString(RET102_SERVICE_REGISTRY_CB_INFO->CompleteName, &RET102_SERVICE_REGISTRY_KEY_PROT_NAME, TRUE))
			{
				return STATUS_ACCESS_DENIED;
			}
		}
		break;
	}
	}
	return STATUS_SUCCESS;
}
```
![image](https://github.com/Koi0x/stackspray-research/assets/95584654/01b12e6f-bef1-421a-aaca-e3f73cc3a1c9)

![image](https://github.com/Koi0x/stackspray-research/assets/95584654/285a1107-437d-4c4f-929b-a11b890b8035)

