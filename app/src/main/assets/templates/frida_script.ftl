/*  Android TODO: Describe
	by Tristan SALAUN

	Run with:
	frida -U -f [APP_ID] -l NAME_OF_THE_SCRIPT.js --no-pause
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
    console.log('');
    console.log('======');
    console.log('[#] Hook of ${model.name} [#]');
    console.log('======');

    // **************************************************
    <#assign constructorCounter = 0>
    <#list model.constructors as constructor>
        // ----- Constructor -----
        <#assign parametersNames = constructor.parameters?map(parameter -> parameter.name)>
        <#assign parametersTypes = constructor.parameters?map(parameter -> "'${parameter.type}'")>
        try {
            Java.use('${model.name}').$init.overload(${parametersTypes?join(", ")}).implementation = function(${parametersNames?join(", ")}) {
                console.log("${model.name}.constructor (${constructorCounter})");
                <#list constructor.parameters as parameter>
                <#if parameter.type == "[B">
                console.log("${parameter.name}: " + toHexString(${parameter.name}) + " | " + toAsciiString(${parameter.name}));
                <#else>
                console.log("${parameter.name}: " + ${parameter.name});
                </#if>
                </#list>
                return this.$init.apply(this, arguments);
            };
        } catch (err) {
            console.log('[-] ${model.name}.Constructor pinner (${constructorCounter}) not found');
            console.log(err);
        }
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
        try {
            Java.use('${model.name}').${method.name}.overload(${parametersTypes?join(", ")}).implementation = function(${parametersNames?join(", ")}) {
                <#if isMultipleMethod>
                console.log("${model.name}.${method.name} (${methodCounter})" + this);
                <#else>
                console.log("${model.name}.${method.name}" + this);
                </#if>
                <#list method.parameters as parameter>
                <#if parameter.type == "[B">
                console.log("${parameter.name}: " + toHexString(${parameter.name}) + " | " + toAsciiString(${parameter.name}));
                <#else>
                console.log("${parameter.name}: " + ${parameter.name});
                </#if>
                </#list>
                <#if method.returnType?? && method.returnType != "kotlin.Unit">
                // Return type: ${method.returnType}
                const returnValue = this.${method.name}.apply(this, arguments);
                    <#if isMultipleMethod>
                        <#if method.returnType == "kotlin.ByteArray!">
                console.log('${model.name}.${method.name} (${methodCounter}) return value: ' + toHexString(returnValue) + ' | ' + toAsciiString(returnValue) )
                        <#else>
                console.log('${model.name}.${method.name} (${methodCounter}) return value: ' + returnValue);
                        </#if>
                    <#else>
                        <#if method.returnType == "kotlin.ByteArray!">
                console.log('${model.name}.${method.name} return value: ' + toHexString(returnValue) + ' | ' + toAsciiString(returnValue) );
                        <#else>
                console.log('${model.name}.${method.name} return value: ' + returnValue);
                        </#if>
                    </#if>
                return returnValue;
                </#if>
            };
        } catch (err) {
            <#if isMultipleMethod>
            console.log('[-] ${model.name}.${method.name} pinner (${methodCounter}) not found');
            <#assign methodCounter = methodCounter + 1>
            <#else>
            console.log('[-] ${model.name}.${method.name} pinner not found');
            </#if>
            console.log(err);
        }

    </#list>
});