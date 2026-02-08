<#function displayValue valueName valueType>
    <#if valueType == "[B">
        <#return "' ${valueName}: ' + toHexString(${valueName}) + ' | ' + toAsciiString(${valueName})">
    <#else>
        <#return "' ${valueName}: ' + ${valueName}">
    </#if>
</#function>

/*  Android TODO: Describe
	by Tristan SALAUN

	Run with:
	frida -U -f [APP_ID] -l ${scriptName} --no-pause
*/

function toHexString(byteArray) {
    return '[0x' + Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join(' 0x') + ']'
}
function toAsciiString(byteArray) {
	return Array.from(byteArray, function(byte) {
		return String.fromCharCode(byte);
	}).join('')
}

Java.perform(function() {
    // **************************************************
    <#assign constructorCounter = 0>
    <#list model.constructors as constructor>
        // ----- Constructor -----
        <#assign parametersNames = constructor.parameters?map(parameter -> parameter.name)>
        <#assign parametersTypes = constructor.parameters?map(parameter -> "'${parameter.type}'")>
        <#assign parametersLog = constructor.parameters?map(parameter -> displayValue(parameter.name,parameter.type) )>

        try {
            Java.use('${model.name}').$init.overload(${parametersTypes?join(", ")}).implementation = function(${parametersNames?join(", ")}) {

                send(JSON.stringify({
                    type: '${eventType}',
                    timestamp: Date.now(),
                    sub_type: '${model.name}.constructor (${constructorCounter}) called (' + ${parametersLog?join(" + ")} + ')',
                    value: ''
                }));

                return this.$init.apply(this, arguments);
            };
        } catch (err) { }
        <#assign constructorCounter = constructorCounter + 1>
    </#list>
        // End constructors handling.


        // ************************************************
        // ********** Methods handling ********************
        // ************************************************
    <#assign currentMethodName = "">
    <#assign methodCounter = 1>
    <#assign isMultipleMethod = false>

    <#list model.methods as method>
        <#if currentMethodName == method.name>
            <#assign isMultipleMethod = true>
        // ----- ${method.name} (${methodCounter}) -----
        <#else>
            <#assign currentMethodName = method.name>
            <#assign isMultipleMethod = false>
            <#assign methodCounter = 1>
        // ----- ${method.name} -----
        </#if>
        <#assign parametersNames = method.parameters?map(parameter -> parameter.name)>
        <#assign parametersTypes = method.parameters?map(parameter -> "'${parameter.type}'")>
        <#assign parametersLog   = method.parameters?map(parameter -> displayValue(parameter.name,parameter.type) )>

        try {
            Java.use('${model.name}').${method.name}.overload(${parametersTypes?join(", ")}).implementation = function(${parametersNames?join(", ")}) {
                <#assign logMethodCounter = "">
                <#assign logMethodValue = "">
                <#if isMultipleMethod>
                    <#assign logMethodCounter = " (${methodCounter})">
                </#if>
                <#if method.returnType?? && method.returnType != "kotlin.Unit">
                // Return type: ${method.returnType}
                const returnValue = this.${method.name}.apply(this, arguments);
                    <#if method.returnType == "kotlin.ByteArray!">
                        <#assign logMethodValue = "toHexString(returnValue) + ' | ' + toAsciiString(returnValue)">
                    <#else>
                        <#assign logMethodValue = "returnValue">
                    </#if>
                send(JSON.stringify({
                    type: '${eventType}',
                    timestamp: Date.now(),
                    sub_type: '${model.name}.${method.name}${logMethodCounter} called (' + ${parametersLog?join(" + ")} + ')',
                    value: ${logMethodValue}
                }));
                return returnValue;
                <#else>
                send(JSON.stringify({
                    type: '${eventType}',
                    timestamp: Date.now(),
                    sub_type: '${model.name}.${method.name}${logMethodCounter} called (' + ${parametersLog?join(" + ")} + ')',
                    value: ''
                }));
                </#if>
                <#if isMultipleMethod>
                    <#assign methodCounter = methodCounter + 1>
                </#if>
            };
        } catch (err) {}

    </#list>

    send(JSON.stringify({
        type: 'internal',
        timestamp: Date.now(),
        sub_type: 'scriptLoaded',
        value: '${scriptName}'
    }));
});