package fr.salaun.tristan.reflexionforfrida

import fr.salaun.tristan.reflexionforfrida.model.ClassModel
import fr.salaun.tristan.reflexionforfrida.model.Method
import fr.salaun.tristan.reflexionforfrida.model.Parameter
import freemarker.template.DefaultObjectWrapper
import freemarker.template.TemplateModel
import freemarker.template.TemplateModelException
import freemarker.template.Version

/**
 * Custom FreeMarker object wrapper for Android.
 * Avoids using java.beans.Introspector which is not available on Android.
 * Converts data classes to Maps for FreeMarker template processing.
 */
class AndroidSafeObjectWrapper(cfgVersion: Version) : DefaultObjectWrapper(cfgVersion) {
    @Throws(TemplateModelException::class)
    override fun wrap(obj: Any?): TemplateModel? {
        return when (obj) {
            is Parameter -> wrapParameter(obj)
            is Method -> wrapMethod(obj)
            is ClassModel -> wrapClassModel(obj)
            else -> super.wrap(obj)
        }
    }

    private fun wrapParameter(obj: Parameter): TemplateModel {
        return super.wrap(
            mapOf(
                "name" to obj.name,
                "type" to obj.type,
            )
        )
    }

    private fun wrapMethod(obj: Method): TemplateModel {
        return super.wrap(
            mapOf(
                "name" to obj.name,
                "parameters" to obj.parameters,
                "returnType" to obj.returnType,
            )
        )
    }

    private fun wrapClassModel(obj: ClassModel): TemplateModel {
        return super.wrap(
            mapOf(
                "name" to obj.name,
                "constructors" to obj.constructors,
                "methods" to obj.methods,
            )
        )
    }
}
