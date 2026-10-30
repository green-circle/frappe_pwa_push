import frappe
from frappe import _
import json

from frappe_pwa_push.setup.install import CLIENT_ROLE


def result(success: bool, message: str = "") -> dict:
	return {"success": success, "message": message}


def is_relay_enabled() -> bool:
	return bool(frappe.db.get_single_value("PWA Push Settings", "enabled"))


def get_client_site(site_name: str) -> str:
	"""Return the client site owned by the authenticated API user.

	Clients post their own site_name with every call; it must match the site the API key
	was issued to, so one registered site can never touch another site's tokens.
	"""
	if not is_relay_enabled():
		frappe.throw(_("Push relay is disabled"), frappe.PermissionError)

	if CLIENT_ROLE not in frappe.get_roles():
		frappe.throw(_("Not a registered push client"), frappe.PermissionError)

	# client_site = frappe.db.get_value("PWA Push Client Site", {"user": frappe.session.user}, "name")
	client_site = frappe.db.get_value("PWA Push Client Site", {"name": site_name}, "name")
	if not client_site or client_site != site_name:
		frappe.throw(
			_("Site {0} is not registered with this relay").format(site_name), frappe.PermissionError
		)
	return client_site


def is_project_enabled(project_name: str) -> bool:
	return bool(frappe.db.get_value("PWA Push Project", project_name, "enabled"))


def project_not_configured(project_name: str) -> dict:
	return result(False, _("Push project {0} is not configured on the relay").format(project_name))


def get_firebase_config(project_name: str) -> dict:
    """
    Utility: Fetch and parse the Firebase web config for a PWA Push Project.
    Raises ValidationError if project_name is missing, DoesNotExistError if not found.
    
    :param project_name: The PWA Push Project name (e.g., "edusync")
    :return: dict containing the parsed Firebase config (apiKey, authDomain, projectId, etc.)
    """
    if not project_name:
        frappe.throw(_("project_name is required"), frappe.ValidationError)

    project = frappe.db.get_value(
        "PWA Push Project",
        {"name": project_name, "enabled": 1},
        ["firebase_config", "vapid_public_key"],
        as_dict=True,
    )
    
    if not is_relay_enabled() or not project:
        frappe.throw(_("Push project {0} is not configured").format(project_name), frappe.DoesNotExistError)
    
    if not project.firebase_config:
        frappe.throw(_("Firebase config not set for project {0}").format(project_name))
    
    return json.loads(project.firebase_config)