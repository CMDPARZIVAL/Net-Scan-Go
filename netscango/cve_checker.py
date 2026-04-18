import requests
import time
from .config import Config

class CVEChecker:
    """فحص الثغرات من قاعدة بيانات CVE"""
    
    def __init__(self):
        self.api_url = Config.CVE_API_URL
        self.cache = {}  # للتخزين المؤقت
    
    def search_cve_for_service(self, service_name, version):
        """
        البحث عن CVEs لخدمة معينة
        
        Args:
            service_name: اسم الخدمة (مثل: Apache, OpenSSH)
            version: رقم النسخة (مثل: 2.4.1)
        
        Returns:
            list: قائمة بالثغرات المكتشفة
        """
        if not service_name or not version or version == "Unknown":
            return []
        
        # التحقق من الـ Cache
        cache_key = f"{service_name}_{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            # تنظيف اسم الخدمة
            search_term = f"{service_name} {version}".strip()
            
            # إرسال الطلب للـ API
            response = requests.get(
                f"{self.api_url}{search_term}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = self.parse_cve_results(data)
                
                # حفظ في الـ Cache
                self.cache[cache_key] = vulnerabilities
                
                return vulnerabilities
            else:
                return []
        
        except Exception as e:
            print(f"❌ Error searching CVE: {e}")
            return []
    
    def parse_cve_results(self, data):
        """تحليل نتائج CVE من الـ API"""
        vulnerabilities = []
        
        # أخذ أول 5 نتائج فقط
        for item in data[:5]:
            try:
                vuln = {
                    'cve_id': item.get('id', 'N/A'),
                    'description': item.get('summary', 'No description available')[:300],
                    'severity': self.get_severity(item),
                    'cvss_score': item.get('cvss', 0.0),
                    'published': item.get('Published', 'N/A'),
                    'references': item.get('references', [])[:3]  # أول 3 مراجع
                }
                vulnerabilities.append(vuln)
            except:
                continue
        
        return vulnerabilities
    
    def get_severity(self, cve_data):
        """تحديد مستوى الخطورة بناءً على CVSS Score"""
        try:
            cvss = float(cve_data.get('cvss', 0))
            
            if cvss >= 9.0:
                return "CRITICAL"
            elif cvss >= 7.0:
                return "HIGH"
            elif cvss >= 4.0:
                return "MEDIUM"
            elif cvss > 0:
                return "LOW"
            else:
                return "INFO"
        except:
            return "UNKNOWN"
    
    def check_vulnerable_version(self, service_name, version):
        """
        التحقق من النسخة المعروفة بأنها ضعيفة
        من قاعدة البيانات المحلية
        """
        vulnerable = Config.VULNERABLE_SERVICES.get(service_name, [])
        
        for vuln_version in vulnerable:
            if version.lower() in vuln_version.lower():
                return True, f"Known vulnerable version: {vuln_version}"
        
        return False, None
    
    def get_recommendations(self, vulnerability):
        """الحصول على توصيات الحماية"""
        severity = vulnerability.get('severity', 'UNKNOWN')
        
        recommendations = {
            'CRITICAL': [
                "🚨 إجراء فوري: قم بتحديث أو إيقاف الخدمة المتأثرة",
                "🔒 عزل النظام عن الشبكة حتى يتم الإصلاح",
                "📊 مراجعة سجلات النظام للتحقق من وجود استغلال",
                "🔔 إبلاغ فريق الأمن فوراً"
            ],
            'HIGH': [
                "⚠️ أولوية عالية: التحديث في أقرب وقت ممكن",
                "🛡️ تطبيق قواعد Firewall للحد من التعرض",
                "📝 جدولة صيانة طارئة لإصلاح الثغرة",
                "🔍 مراقبة النظام بشكل مكثف"
            ],
            'MEDIUM': [
                "📅 التخطيط لتحديث الخدمة خلال أسبوع",
                "🔐 تطبيق إجراءات أمان إضافية",
                "📊 توثيق الثغرة في سجل المخاطر",
                "🔄 متابعة التحديثات الأمنية"
            ],
            'LOW': [
                "ℹ️ التحديث في الصيانة الدورية القادمة",
                "📖 مراجعة أفضل الممارسات الأمنية",
                "🔍 المراقبة العادية للنظام"
            ]
        }
        
        return recommendations.get(severity, ["مراجعة التوصيات الأمنية العامة"])
    
    def generate_vulnerability_report(self, vulnerabilities):
        """إنشاء تقرير ملخص للثغرات"""
        if not vulnerabilities:
            return {
                'total': 0,
                'by_severity': {},
                'critical_count': 0,
                'summary': 'No vulnerabilities detected'
            }
        
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total': len(vulnerabilities),
            'by_severity': by_severity,
            'critical_count': by_severity.get('CRITICAL', 0),
            'high_count': by_severity.get('HIGH', 0),
            'summary': f"Found {len(vulnerabilities)} vulnerabilities"
        }