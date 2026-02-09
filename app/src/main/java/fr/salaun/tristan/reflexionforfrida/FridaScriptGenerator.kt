package fr.salaun.tristan.reflexionforfrida

import fr.salaun.tristan.reflexionforfrida.model.ClassModel
import freemarker.template.Configuration
import freemarker.template.TemplateExceptionHandler
import java.io.StringWriter

/**
 * Generates Frida hook scripts from a ClassModel using FreeMarker templates.
 */
class FridaScriptGenerator {

    fun generate(
        model: ClassModel,
        templateName: String,
        scriptName: String,
        eventType: String
    ): String {
        val cfg = Configuration(Configuration.VERSION_2_3_33).apply {
            setClassForTemplateLoading(this::class.java, "/assets/templates")
            defaultEncoding = "UTF-8"
            templateExceptionHandler = TemplateExceptionHandler.RETHROW_HANDLER
            objectWrapper = AndroidSafeObjectWrapper(Configuration.VERSION_2_3_33)
        }

        val template = cfg.getTemplate(templateName)

        val dataModel = mapOf(
            "model" to model,
            "scriptName" to scriptName,
            "eventType" to eventType
        )

        val out = StringWriter()
        template.process(dataModel, out)
        return out.toString()
    }
}
