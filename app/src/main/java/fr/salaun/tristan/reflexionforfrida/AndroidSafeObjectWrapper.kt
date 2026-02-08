package fr.salaun.tristan.reflexionforfrida

import freemarker.template.DefaultObjectWrapper
import freemarker.template.TemplateModel
import freemarker.template.TemplateModelException
import freemarker.template.Version

/**
 * This class is mandatory under Android to avoid the error: java.lang.ClassNotFoundException: Didn't find class "java.beans.Introspector"
 * It allows to perform "hardcoded reflexion".
 */
class AndroidSafeObjectWrapper(cfgVersion: Version) : DefaultObjectWrapper(cfgVersion) {
    @Throws(TemplateModelException::class)
    override fun wrap(obj: Any?): TemplateModel? {
        return when (obj) {
            is MainActivity.Parameter -> wrapParameterWithoutIntrospection(obj)
            is MainActivity.Method -> wrapMethodWithoutIntrospection(obj)
            is MainActivity.Model -> wrapModelWithoutIntrospection(obj)
            else -> super.wrap(obj)
        }
    }

    private fun wrapParameterWithoutIntrospection(obj: MainActivity.Parameter): TemplateModel {
        // Custom wrapping logic to avoid introspection.
        return super.wrap(
            mapOf(
                "name" to obj.name,
                "type" to obj.type,
            )
        )
    }

    private fun wrapMethodWithoutIntrospection(obj: MainActivity.Method): TemplateModel {
        // Custom wrapping logic to avoid introspection.
        return super.wrap(
            mapOf(
                "name" to obj.name,
                "parameters" to obj.parameters,
                "returnType" to obj.returnType,
            )
        )
    }

    private fun wrapModelWithoutIntrospection(obj: MainActivity.Model): TemplateModel {
        // Custom wrapping logic to avoid introspection.
        return super.wrap(
            mapOf(
                "name" to obj.name,
                "constructors" to obj.constructors,
                "methods" to obj.methods,
            )
        )
    }
}