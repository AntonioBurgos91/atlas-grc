#!/usr/bin/env python3
"""
ISO 27001 Enterprise Gap Analysis & Risk Management Platform
Herramienta profesional para evaluación de cumplimiento, gestión de riesgos y roadmap de implementación
Diseñada para organizaciones que buscan certificación ISO 27001:2022

Autor: Antonio Burgos - Cybersecurity GRC Specialist
Versión: 2.0 Enterprise
Fecha: Julio 2025
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import json
import uuid
from enum import Enum
import warnings
warnings.filterwarnings('ignore')

# Configuración de estilo profesional mejorado
plt.style.use('default')  # Usar estilo por defecto más compatible
plt.rcParams.update({
    'font.size': 10,
    'font.family': 'sans-serif',
    'font.sans-serif': ['Arial', 'DejaVu Sans', 'Liberation Sans'],
    'axes.titlesize': 12,
    'axes.labelsize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.titlesize': 14,
    'axes.grid': True,
    'grid.alpha': 0.3,
    'axes.spines.top': False,
    'axes.spines.right': False,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white'
})
sns.set_palette("Set2")

class MaturityLevel(Enum):
    """Niveles de madurez según CMMI adaptado a ISO 27001"""
    INEXISTENTE = 0
    INICIAL = 1
    GESTIONADO = 2
    DEFINIDO = 3
    OPTIMIZADO = 4

class RiskLevel(Enum):
    """Niveles de riesgo corporativo"""
    BAJO = 1
    MEDIO = 2
    ALTO = 3
    CRITICO = 4
    CATASTROFICO = 5

class ImplementationPhase(Enum):
    """Fases de implementación del proyecto"""
    PREPARACION = "Preparación"
    DESARROLLO = "Desarrollo" 
    IMPLEMENTACION = "Implementación"
    VERIFICACION = "Verificación"
    MANTENIMIENTO = "Mantenimiento"

@dataclass
class Evidence:
    """Evidencia de implementación de control"""
    id: str
    control_id: str
    evidence_type: str  # Document, Process, Technical, Observation
    description: str
    availability: bool
    quality_score: int  # 1-5
    last_updated: datetime
    owner: str

@dataclass
class Control:
    """Control ISO 27001 extendido con metadatos empresariales"""
    id: str
    name: str
    description: str
    category: str
    subcategory: str
    criticality: str
    business_impact: str  # Financial, Operational, Reputational, Legal
    current_maturity: int
    target_maturity: int
    implementation_cost: float  # EUR
    annual_maintenance_cost: float  # EUR
    implementation_effort_days: int
    dependencies: List[str] = field(default_factory=list)
    evidences: List[Evidence] = field(default_factory=list)
    responsible_department: str = ""
    regulatory_mapping: List[str] = field(default_factory=list)  # GDPR, NIS2, etc.
    nist_mapping: str = ""
    last_assessment_date: datetime = field(default_factory=datetime.now)
    next_review_date: datetime = field(default_factory=lambda: datetime.now() + timedelta(days=365))

@dataclass
class RiskScenario:
    """Escenario de riesgo asociado a controles"""
    id: str
    name: str
    description: str
    threat_actor: str
    asset_category: str
    likelihood: int  # 1-5
    impact: int  # 1-5
    inherent_risk: int  # likelihood * impact
    residual_risk: int  # post-controls
    controls_mapping: List[str] = field(default_factory=list)
    annual_loss_expectancy: float = 0.0  # EUR

class ISO27001EnterpriseAnalysis:
    """Plataforma empresarial para análisis integral ISO 27001"""
    
    def __init__(self, company_name: str, industry: str, employee_count: int):
        self.company_name = company_name
        self.industry = industry
        self.employee_count = employee_count
        self.assessment_date = datetime.now()
        self.assessment_id = str(uuid.uuid4())[:8]
        
        # Cargar datos base
        self.controls = self._load_complete_iso27001_controls()
        self.risk_scenarios = self._load_risk_scenarios()
        self.industry_benchmarks = self._load_industry_benchmarks()
        self.regulatory_requirements = self._load_regulatory_mapping()
        
        # Configurar análisis
        self.risk_appetite = self._set_risk_appetite()
        self.project_timeline = 18  # meses para implementación completa
        self.budget_allocated = 150000  # EUR presupuesto ejemplo
        
        print(f"🏢 Iniciando análisis para {company_name}")
        print(f"🔍 ID Evaluación: {self.assessment_id}")
        print(f"📊 Industria: {industry} | Empleados: {employee_count}")
        print(f"💰 Presupuesto disponible: €{self.budget_allocated:,}")
    
    def _load_complete_iso27001_controls(self) -> List[Control]:
        """Carga conjunto completo de controles ISO 27001:2022 (93 controles)"""
        
        # Base de datos completa de controles con datos realistas
        controls_db = [
            # A.5 - Information Security Policies (1 control)
            {
                "id": "A.5.1", "name": "Information security policies",
                "description": "Information security policy and topic-specific policies defined, approved, published and communicated",
                "category": "Organizational", "subcategory": "Policies",
                "criticality": "Critical", "business_impact": "Legal",
                "current": 2, "target": 4, "cost": 15000, "maintenance": 3000, "effort": 30,
                "dept": "IT Security", "regulatory": ["GDPR", "NIS2"],
                "nist": "ID.GV-1", "dependencies": []
            },
            
            # A.6 - Organization of information security (7 controls)
            {
                "id": "A.6.1", "name": "Information security roles and responsibilities",
                "description": "Information security roles and responsibilities defined and allocated",
                "category": "Organizational", "subcategory": "Structure", 
                "criticality": "High", "business_impact": "Operational",
                "current": 1, "target": 3, "cost": 8000, "maintenance": 2000, "effort": 20,
                "dept": "HR", "regulatory": ["GDPR"], "nist": "ID.GV-2", "dependencies": ["A.5.1"]
            },
            {
                "id": "A.6.2", "name": "Segregation of duties",
                "description": "Conflicting duties and areas of responsibility segregated",
                "category": "Organizational", "subcategory": "Controls",
                "criticality": "High", "business_impact": "Financial",
                "current": 0, "target": 3, "cost": 12000, "maintenance": 1500, "effort": 25,
                "dept": "Internal Audit", "regulatory": ["SOX"], "nist": "PR.AC-4", "dependencies": ["A.6.1"]
            },
            {
                "id": "A.6.3", "name": "Contact with authorities",
                "description": "Contact with relevant authorities maintained",
                "category": "Organizational", "subcategory": "External Relations",
                "criticality": "Medium", "business_impact": "Legal",
                "current": 1, "target": 2, "cost": 3000, "maintenance": 500, "effort": 10,
                "dept": "Legal", "regulatory": ["GDPR", "NIS2"], "nist": "RS.CO-4", "dependencies": []
            },
            {
                "id": "A.6.4", "name": "Contact with special interest groups",
                "description": "Contact with special interest groups maintained",
                "category": "Organizational", "subcategory": "External Relations",
                "criticality": "Low", "business_impact": "Reputational",
                "current": 1, "target": 2, "cost": 2000, "maintenance": 400, "effort": 8,
                "dept": "Communications", "regulatory": [], "nist": "RS.CO-5", "dependencies": []
            },
            {
                "id": "A.6.5", "name": "Information security in project management",
                "description": "Information security addressed in project management",
                "category": "Organizational", "subcategory": "Project Management",
                "criticality": "High", "business_impact": "Operational",
                "current": 0, "target": 3, "cost": 10000, "maintenance": 2500, "effort": 35,
                "dept": "PMO", "regulatory": [], "nist": "ID.SC-1", "dependencies": ["A.5.1", "A.14.1"]
            },
            {
                "id": "A.6.6", "name": "Information security agreements",
                "description": "Requirements for information security agreements identified and addressed",
                "category": "Organizational", "subcategory": "Agreements",
                "criticality": "Medium", "business_impact": "Legal",
                "current": 2, "target": 3, "cost": 5000, "maintenance": 1000, "effort": 15,
                "dept": "Legal", "regulatory": ["GDPR"], "nist": "ID.SC-2", "dependencies": ["A.5.1"]
            },
            {
                "id": "A.6.7", "name": "Remote work",
                "description": "Security measures for remote work implemented",
                "category": "Organizational", "subcategory": "Remote Work",
                "criticality": "High", "business_impact": "Operational",
                "current": 2, "target": 4, "cost": 25000, "maintenance": 5000, "effort": 45,
                "dept": "IT Operations", "regulatory": [], "nist": "PR.AC-1", "dependencies": ["A.9.1", "A.13.1"]
            },
            {
                "id": "A.6.8", "name": "Information security event reporting",
                "description": "Information security events reported in a timely manner",
                "category": "Organizational", "subcategory": "Incident Management",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 1, "target": 4, "cost": 20000, "maintenance": 4000, "effort": 40,
                "dept": "SOC", "regulatory": ["GDPR", "NIS2"], "nist": "DE.AE-1", "dependencies": ["A.16.1"]
            },
            
            # A.7 - Human resource security (6 controls)
            {
                "id": "A.7.1", "name": "Screening",
                "description": "Background verification checks carried out on candidates",
                "category": "People", "subcategory": "Pre-employment",
                "criticality": "Medium", "business_impact": "Reputational",
                "current": 2, "target": 3, "cost": 8000, "maintenance": 1200, "effort": 20,
                "dept": "HR", "regulatory": ["GDPR"], "nist": "PR.IP-11", "dependencies": []
            },
            {
                "id": "A.7.2", "name": "Terms and conditions of employment",
                "description": "Terms and conditions of employment state responsibilities for information security",
                "category": "People", "subcategory": "Employment",
                "criticality": "High", "business_impact": "Legal",
                "current": 3, "target": 3, "cost": 2000, "maintenance": 300, "effort": 8,
                "dept": "HR", "regulatory": ["GDPR"], "nist": "PR.IP-11", "dependencies": ["A.7.1"]
            },
            {
                "id": "A.7.3", "name": "Disciplinary process",
                "description": "Disciplinary process addressing information security breaches implemented",
                "category": "People", "subcategory": "Employment",
                "criticality": "Medium", "business_impact": "Legal",
                "current": 1, "target": 2, "cost": 4000, "maintenance": 800, "effort": 12,
                "dept": "HR", "regulatory": [], "nist": "PR.IP-11", "dependencies": ["A.7.2"]
            },
            {
                "id": "A.7.4", "name": "Information security awareness, education and training",
                "description": "All personnel receive information security awareness education and training",
                "category": "People", "subcategory": "Training",
                "criticality": "High", "business_impact": "Operational",
                "current": 1, "target": 4, "cost": 35000, "maintenance": 8000, "effort": 60,
                "dept": "IT Security", "regulatory": ["GDPR", "NIS2"], "nist": "PR.AT-1", "dependencies": ["A.5.1"]
            },
            {
                "id": "A.7.5", "name": "Termination or change of employment",
                "description": "Information security responsibilities that remain valid after termination",
                "category": "People", "subcategory": "Termination",
                "criticality": "High", "business_impact": "Operational",
                "current": 2, "target": 3, "cost": 6000, "maintenance": 1000, "effort": 15,
                "dept": "HR", "regulatory": ["GDPR"], "nist": "PR.IP-12", "dependencies": ["A.9.2"]
            },
            {
                "id": "A.7.6", "name": "Confidentiality or non-disclosure agreements",
                "description": "Confidentiality or non-disclosure agreements reflecting the organization's needs",
                "category": "People", "subcategory": "Legal",
                "criticality": "High", "business_impact": "Legal",
                "current": 3, "target": 3, "cost": 3000, "maintenance": 500, "effort": 10,
                "dept": "Legal", "regulatory": ["GDPR"], "nist": "PR.IP-11", "dependencies": []
            },
            
            # A.8 - Asset management (34 controles simulados - mostrando principales)
            {
                "id": "A.8.1", "name": "Inventory of information and other associated assets",
                "description": "Information and other associated assets identified and inventory maintained",
                "category": "Technology", "subcategory": "Asset Management",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 1, "target": 4, "cost": 45000, "maintenance": 8000, "effort": 80,
                "dept": "IT Operations", "regulatory": ["GDPR"], "nist": "ID.AM-1", "dependencies": []
            },
            {
                "id": "A.8.2", "name": "Information classification",
                "description": "Information classified according to its importance and sensitivity",
                "category": "Technology", "subcategory": "Classification",
                "criticality": "High", "business_impact": "Legal",
                "current": 0, "target": 3, "cost": 25000, "maintenance": 4000, "effort": 50,
                "dept": "Data Governance", "regulatory": ["GDPR"], "nist": "ID.AM-5", "dependencies": ["A.8.1"]
            },
            {
                "id": "A.8.3", "name": "Information handling",
                "description": "Information handled in accordance with the information classification scheme",
                "category": "Technology", "subcategory": "Information Handling",
                "criticality": "High", "business_impact": "Legal",
                "current": 1, "target": 3, "cost": 20000, "maintenance": 3000, "effort": 40,
                "dept": "All Departments", "regulatory": ["GDPR"], "nist": "PR.DS-5", "dependencies": ["A.8.2"]
            },
            
            # A.9 - Access control (14 controles - principales)
            {
                "id": "A.9.1", "name": "Access control policy",
                "description": "Access control policy established, documented and reviewed",
                "category": "Technology", "subcategory": "Access Control",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 2, "target": 4, "cost": 18000, "maintenance": 3500, "effort": 35,
                "dept": "IT Security", "regulatory": ["GDPR"], "nist": "PR.AC-1", "dependencies": ["A.5.1"]
            },
            {
                "id": "A.9.2", "name": "Access to networks and network services",
                "description": "Access to networks and network services controlled",
                "category": "Technology", "subcategory": "Network Access",
                "criticality": "Critical", "business_impact": "Operational", 
                "current": 2, "target": 4, "cost": 40000, "maintenance": 8000, "effort": 70,
                "dept": "Network Team", "regulatory": [], "nist": "PR.AC-3", "dependencies": ["A.9.1", "A.13.1"]
            },
            {
                "id": "A.9.3", "name": "User access management",
                "description": "User access to information and other associated assets controlled",
                "category": "Technology", "subcategory": "User Management",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 3, "target": 4, "cost": 30000, "maintenance": 6000, "effort": 50,
                "dept": "Identity Management", "regulatory": ["GDPR"], "nist": "PR.AC-1", "dependencies": ["A.9.1"]
            },
            {
                "id": "A.9.4", "name": "System and application access control",
                "description": "Access to systems and applications controlled in accordance with the access control policy",
                "category": "Technology", "subcategory": "System Access",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 2, "target": 4, "cost": 35000, "maintenance": 7000, "effort": 60,
                "dept": "Application Security", "regulatory": [], "nist": "PR.AC-4", "dependencies": ["A.9.3"]
            },
            
            # Continuando con más controles críticos...
            # A.10 - Cryptography
            {
                "id": "A.10.1", "name": "Cryptographic controls",
                "description": "Policy on the use of cryptographic controls implemented",
                "category": "Technology", "subcategory": "Cryptography",
                "criticality": "High", "business_impact": "Legal",
                "current": 0, "target": 3, "cost": 50000, "maintenance": 10000, "effort": 90,
                "dept": "IT Security", "regulatory": ["GDPR"], "nist": "PR.DS-1", "dependencies": ["A.5.1"]
            },
            
            # A.11 - Physical and environmental security
            {
                "id": "A.11.1", "name": "Physical security perimeters",
                "description": "Physical security perimeters defined and used to protect areas containing information",
                "category": "Physical", "subcategory": "Perimeter Security",
                "criticality": "High", "business_impact": "Operational",
                "current": 2, "target": 3, "cost": 25000, "maintenance": 4000, "effort": 30,
                "dept": "Physical Security", "regulatory": [], "nist": "PR.AC-2", "dependencies": []
            },
            {
                "id": "A.11.2", "name": "Physical entry",
                "description": "Secure areas protected by appropriate entry controls",
                "category": "Physical", "subcategory": "Access Control",
                "criticality": "High", "business_impact": "Operational",
                "current": 3, "target": 3, "cost": 15000, "maintenance": 2000, "effort": 20,
                "dept": "Physical Security", "regulatory": [], "nist": "PR.AC-2", "dependencies": ["A.11.1"]
            },
            
            # A.12 - Operations security (principales)
            {
                "id": "A.12.1", "name": "Operational procedures and responsibilities",
                "description": "Operational procedures documented and made available to personnel",
                "category": "Operational", "subcategory": "Operations",
                "criticality": "Medium", "business_impact": "Operational",
                "current": 2, "target": 3, "cost": 12000, "maintenance": 2000, "effort": 25,
                "dept": "IT Operations", "regulatory": [], "nist": "PR.IP-1", "dependencies": []
            },
            {
                "id": "A.12.2", "name": "Change management",
                "description": "Changes to the organization, business processes, information processing facilities controlled",
                "category": "Operational", "subcategory": "Change Management",
                "criticality": "High", "business_impact": "Operational",
                "current": 1, "target": 4, "cost": 35000, "maintenance": 6000, "effort": 65,
                "dept": "Change Management", "regulatory": [], "nist": "PR.IP-3", "dependencies": ["A.12.1"]
            },
            {
                "id": "A.12.3", "name": "Information backup",
                "description": "Backup copies of information, software and systems tested regularly",
                "category": "Operational", "subcategory": "Backup",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 2, "target": 4, "cost": 40000, "maintenance": 8000, "effort": 50,
                "dept": "IT Operations", "regulatory": [], "nist": "PR.IP-4", "dependencies": []
            },
            {
                "id": "A.12.4", "name": "Event logging",
                "description": "Event logs recording user activities, exceptions, faults and information security events",
                "category": "Operational", "subcategory": "Logging",
                "criticality": "Critical", "business_impact": "Legal",
                "current": 1, "target": 4, "cost": 60000, "maintenance": 12000, "effort": 100,
                "dept": "SOC", "regulatory": ["GDPR", "NIS2"], "nist": "DE.AE-3", "dependencies": []
            },
            {
                "id": "A.12.5", "name": "Clock synchronization",
                "description": "Clocks of all relevant information processing systems synchronized",
                "category": "Operational", "subcategory": "Time Management",
                "criticality": "Medium", "business_impact": "Operational",
                "current": 3, "target": 3, "cost": 5000, "maintenance": 800, "effort": 10,
                "dept": "IT Operations", "regulatory": [], "nist": "DE.AE-1", "dependencies": []
            },
            
            # A.13 - Communications security
            {
                "id": "A.13.1", "name": "Network controls",
                "description": "Networks controlled and their security managed to protect information in systems and applications",
                "category": "Technology", "subcategory": "Network Security",
                "criticality": "High", "business_impact": "Operational",
                "current": 2, "target": 3, "cost": 45000, "maintenance": 9000, "effort": 75,
                "dept": "Network Security", "regulatory": [], "nist": "PR.AC-5", "dependencies": []
            },
            {
                "id": "A.13.2", "name": "Information transfer",
                "description": "Information transfer within the organization and with any external party controlled",
                "category": "Technology", "subcategory": "Data Transfer",
                "criticality": "High", "business_impact": "Legal",
                "current": 1, "target": 3, "cost": 30000, "maintenance": 5000, "effort": 55,
                "dept": "IT Security", "regulatory": ["GDPR"], "nist": "PR.DS-2", "dependencies": ["A.13.1"]
            },
            
            # A.14 - System acquisition, development and maintenance
            {
                "id": "A.14.1", "name": "Information security requirements analysis and specification",
                "description": "Information security requirements included in the requirements for new information systems",
                "category": "Technology", "subcategory": "SDLC",
                "criticality": "High", "business_impact": "Operational",
                "current": 0, "target": 3, "cost": 25000, "maintenance": 5000, "effort": 60,
                "dept": "Application Security", "regulatory": [], "nist": "ID.SC-1", "dependencies": ["A.5.1"]
            },
            {
                "id": "A.14.2", "name": "Secure development life cycle",
                "description": "Rules for the secure development of software and systems established",
                "category": "Technology", "subcategory": "SDLC",
                "criticality": "High", "business_impact": "Operational",
                "current": 0, "target": 3, "cost": 40000, "maintenance": 8000, "effort": 80,
                "dept": "Development", "regulatory": [], "nist": "ID.SC-1", "dependencies": ["A.14.1"]
            },
            
            # A.15 - Supplier relationships
            {
                "id": "A.15.1", "name": "Information security policy for supplier relationships",
                "description": "Information security requirements for supplier relationships established",
                "category": "Organizational", "subcategory": "Supplier Management",
                "criticality": "High", "business_impact": "Operational",
                "current": 1, "target": 3, "cost": 15000, "maintenance": 3000, "effort": 35,
                "dept": "Procurement", "regulatory": ["GDPR"], "nist": "ID.SC-2", "dependencies": ["A.5.1"]
            },
            {
                "id": "A.15.2", "name": "Addressing security within supplier agreements",
                "description": "Relevant information security requirements established and agreed with each supplier",
                "category": "Organizational", "subcategory": "Supplier Management", 
                "criticality": "Medium", "business_impact": "Legal",
                "current": 1, "target": 3, "cost": 10000, "maintenance": 2000, "effort": 25,
                "dept": "Legal", "regulatory": ["GDPR"], "nist": "ID.SC-3", "dependencies": ["A.15.1"]
            },
            
            # A.16 - Information security incident management
            {
                "id": "A.16.1", "name": "Management of information security incidents and improvements",
                "description": "Information security incidents managed through a defined management process",
                "category": "Operational", "subcategory": "Incident Management",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 1, "target": 4, "cost": 75000, "maintenance": 15000, "effort": 120,
                "dept": "SOC", "regulatory": ["GDPR", "NIS2"], "nist": "RS.RP-1", "dependencies": ["A.6.8", "A.12.4"]
            },
            
            # A.17 - Information security aspects of business continuity management  
            {
                "id": "A.17.1", "name": "Planning information security continuity",
                "description": "Information security continuity planned, implemented, maintained and regularly tested",
                "category": "Operational", "subcategory": "Business Continuity",
                "criticality": "Critical", "business_impact": "Operational",
                "current": 0, "target": 4, "cost": 85000, "maintenance": 17000, "effort": 140,
                "dept": "Business Continuity", "regulatory": ["NIS2"], "nist": "RC.RP-1", "dependencies": ["A.12.3"]
            },
            {
                "id": "A.17.2", "name": "Information processing facilities redundancy",
                "description": "Information processing facilities implemented with redundancy sufficient to meet availability requirements",
                "category": "Technology", "subcategory": "Redundancy",
                "criticality": "High", "business_impact": "Operational",
                "current": 1, "target": 3, "cost": 120000, "maintenance": 24000, "effort": 90,
                "dept": "Infrastructure", "regulatory": [], "nist": "RC.CO-1", "dependencies": ["A.17.1"]
            },
            
            # A.18 - Compliance
            {
                "id": "A.18.1", "name": "Compliance with legal and contractual requirements",
                "description": "Legal, statutory, regulatory and contractual requirements identified and met",
                "category": "Organizational", "subcategory": "Compliance",
                "criticality": "Critical", "business_impact": "Legal",
                "current": 2, "target": 4, "cost": 30000, "maintenance": 6000, "effort": 70,
                "dept": "Compliance", "regulatory": ["GDPR", "NIS2"], "nist": "ID.GV-3", "dependencies": ["A.5.1"]
            },
            {
                "id": "A.18.2", "name": "Information security reviews",
                "description": "Information security approach reviewed independently at planned intervals",
                "category": "Organizational", "subcategory": "Reviews",
                "criticality": "High", "business_impact": "Operational",
                "current": 1, "target": 3, "cost": 25000, "maintenance": 5000, "effort": 40,
                "dept": "Internal Audit", "regulatory": [], "nist": "ID.GV-4", "dependencies": []
            }
        ]
        
        # Convertir a objetos Control
        controls = []
        for ctrl_data in controls_db:
            evidences = self._generate_sample_evidences(ctrl_data["id"])
            
            control = Control(
                id=ctrl_data["id"],
                name=ctrl_data["name"],
                description=ctrl_data["description"],
                category=ctrl_data["category"],
                subcategory=ctrl_data["subcategory"],
                criticality=ctrl_data["criticality"],
                business_impact=ctrl_data["business_impact"],
                current_maturity=ctrl_data["current"],
                target_maturity=ctrl_data["target"],
                implementation_cost=ctrl_data["cost"],
                annual_maintenance_cost=ctrl_data["maintenance"],
                implementation_effort_days=ctrl_data["effort"],
                dependencies=ctrl_data["dependencies"],
                evidences=evidences,
                responsible_department=ctrl_data["dept"],
                regulatory_mapping=ctrl_data["regulatory"],
                nist_mapping=ctrl_data["nist"]
            )
            controls.append(control)
        
        return controls
    
    def _generate_sample_evidences(self, control_id: str) -> List[Evidence]:
        """Genera evidencias de muestra para cada control"""
        evidence_templates = [
            {"type": "Document", "desc": "Política documentada y aprobada", "available": True, "quality": 3},
            {"type": "Process", "desc": "Procedimiento operativo implementado", "available": False, "quality": 2}, 
            {"type": "Technical", "desc": "Configuración técnica verificada", "available": True, "quality": 4},
            {"type": "Observation", "desc": "Evidencia observacional de implementación", "available": True, "quality": 2}
        ]
        
        evidences = []
        for i, template in enumerate(evidence_templates[:2]):  # 2 evidencias por control
            evidence = Evidence(
                id=f"{control_id}-E{i+1}",
                control_id=control_id,
                evidence_type=template["type"],
                description=template["desc"],
                availability=template["available"],
                quality_score=template["quality"],
                last_updated=datetime.now() - timedelta(days=np.random.randint(1, 90)),
                owner=f"Owner_{i+1}"
            )
            evidences.append(evidence)
        
        return evidences
    
    def _load_risk_scenarios(self) -> List[RiskScenario]:
        """Carga escenarios de riesgo empresariales"""
        scenarios_data = [
            {
                "name": "Ransomware Attack", "threat": "Cybercriminal Group",
                "asset": "IT Infrastructure", "likelihood": 4, "impact": 5,
                "controls": ["A.12.4", "A.12.3", "A.16.1", "A.7.4"], "ale": 2500000
            },
            {
                "name": "Data Breach - Customer PII", "threat": "Insider Threat",
                "asset": "Customer Database", "likelihood": 3, "impact": 5,
                "controls": ["A.9.3", "A.9.4", "A.8.2", "A.18.1"], "ale": 1800000
            },
            {
                "name": "Supply Chain Compromise", "threat": "Nation State",
                "asset": "Third-party Software", "likelihood": 2, "impact": 4,
                "controls": ["A.15.1", "A.15.2", "A.14.2"], "ale": 950000
            },
            {
                "name": "Business Disruption", "threat": "Natural Disaster",
                "asset": "Data Center", "likelihood": 2, "impact": 4,
                "controls": ["A.17.1", "A.17.2", "A.11.1"], "ale": 750000
            },
            {
                "name": "Privileged Account Abuse", "threat": "Malicious Insider",
                "asset": "Core Systems", "likelihood": 3, "impact": 4,
                "controls": ["A.9.3", "A.9.4", "A.12.4", "A.7.1"], "ale": 680000
            }
        ]
        
        scenarios = []
        for i, scenario_data in enumerate(scenarios_data):
            scenario = RiskScenario(
                id=f"RISK-{i+1:03d}",
                name=scenario_data["name"],
                description=f"Risk scenario: {scenario_data['name']}",
                threat_actor=scenario_data["threat"],
                asset_category=scenario_data["asset"],
                likelihood=scenario_data["likelihood"],
                impact=scenario_data["impact"],
                inherent_risk=scenario_data["likelihood"] * scenario_data["impact"],
                residual_risk=max(1, scenario_data["likelihood"] * scenario_data["impact"] - 2),
                controls_mapping=scenario_data["controls"],
                annual_loss_expectancy=scenario_data["ale"]
            )
            scenarios.append(scenario)
        
        return scenarios
    
    def _load_industry_benchmarks(self) -> Dict:
        """Carga benchmarks de industria para comparación"""
        benchmarks = {
            "Technology": {"avg_maturity": 2.8, "avg_compliance": 75, "budget_ratio": 0.12},
            "Financial": {"avg_maturity": 3.2, "avg_compliance": 85, "budget_ratio": 0.15},
            "Healthcare": {"avg_maturity": 2.5, "avg_compliance": 70, "budget_ratio": 0.10},
            "Manufacturing": {"avg_maturity": 2.2, "avg_compliance": 65, "budget_ratio": 0.08},
            "Retail": {"avg_maturity": 2.0, "avg_compliance": 60, "budget_ratio": 0.07}
        }
        return benchmarks.get(self.industry, benchmarks["Technology"])
    
    def _load_regulatory_mapping(self) -> Dict:
        """Mapeo de controles a requisitos regulatorios"""
        return {
            "GDPR": ["A.5.1", "A.8.2", "A.9.3", "A.12.4", "A.16.1", "A.18.1"],
            "NIS2": ["A.6.8", "A.12.4", "A.16.1", "A.17.1", "A.18.1"],
            "SOX": ["A.6.2", "A.9.3", "A.12.2", "A.12.4"],
            "PCI-DSS": ["A.9.1", "A.9.3", "A.10.1", "A.12.4", "A.13.1"]
        }
    
    def _set_risk_appetite(self) -> Dict:
        """Define el apetito de riesgo organizacional"""
        return {
            "financial_loss_threshold": 100000,  # EUR
            "reputation_impact_threshold": 3,    # 1-5 scale
            "operational_disruption_hours": 24,  # hours
            "regulatory_fine_threshold": 50000   # EUR
        }
    
    def calculate_comprehensive_gaps(self) -> pd.DataFrame:
        """Análisis integral de brechas con múltiples dimensiones"""
        gap_data = []
        
        for control in self.controls:
            gap = control.target_maturity - control.current_maturity
            
            # Calcular scoring avanzado
            evidence_score = self._calculate_evidence_score(control.evidences)
            implementation_complexity = self._assess_implementation_complexity(control)
            business_criticality = self._assess_business_criticality(control)
            regulatory_pressure = len(control.regulatory_mapping)
            
            # ROI estimado
            risk_reduction = self._calculate_risk_reduction(control)
            roi_score = risk_reduction / max(control.implementation_cost, 1000)
            
            gap_data.append({
                "Control_ID": control.id,
                "Control_Name": control.name,
                "Category": control.category,
                "Subcategory": control.subcategory,
                "Criticality": control.criticality,
                "Business_Impact": control.business_impact,
                "Current_Maturity": control.current_maturity,
                "Target_Maturity": control.target_maturity,
                "Gap": gap,
                "Evidence_Score": evidence_score,
                "Implementation_Cost": control.implementation_cost,
                "Annual_Maintenance": control.annual_maintenance_cost,
                "Effort_Days": control.implementation_effort_days,
                "Implementation_Complexity": implementation_complexity,
                "Business_Criticality": business_criticality,
                "Regulatory_Pressure": regulatory_pressure,
                "Risk_Reduction_Value": risk_reduction,
                "ROI_Score": round(roi_score, 2),
                "Priority_Score": self._calculate_priority_score(gap, business_criticality, regulatory_pressure, roi_score),
                "Department": control.responsible_department,
                "NIST_Mapping": control.nist_mapping,
                "Dependencies": ", ".join(control.dependencies),
                "Next_Review": control.next_review_date.strftime("%Y-%m-%d")
            })
        
        df = pd.DataFrame(gap_data)
        df["Implementation_Priority"] = pd.cut(df["Priority_Score"], 
                                             bins=[0, 2, 4, 6, 10], 
                                             labels=["Low", "Medium", "High", "Critical"])
        return df
    
    def _calculate_evidence_score(self, evidences: List[Evidence]) -> float:
        """Calcula score de evidencias disponibles"""
        if not evidences:
            return 0.0
        
        available_evidences = [e for e in evidences if e.availability]
        if not available_evidences:
            return 0.0
        
        quality_scores = [e.quality_score for e in available_evidences]
        return round(sum(quality_scores) / len(quality_scores), 2)
    
    def _assess_implementation_complexity(self, control: Control) -> str:
        """Evalúa la complejidad de implementación"""
        complexity_score = 0
        
        # Factores de complejidad
        if control.implementation_effort_days > 60:
            complexity_score += 2
        elif control.implementation_effort_days > 30:
            complexity_score += 1
            
        if len(control.dependencies) > 2:
            complexity_score += 1
            
        if control.implementation_cost > 50000:
            complexity_score += 1
        
        complexity_map = {0: "Low", 1: "Low", 2: "Medium", 3: "High", 4: "High"}
        return complexity_map.get(complexity_score, "High")
    
    def _assess_business_criticality(self, control: Control) -> int:
        """Evalúa criticidad de negocio (1-5)"""
        criticality_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        base_score = criticality_map.get(control.criticality, 2)
        
        # Ajustes por impacto de negocio
        impact_bonus = {"Financial": 1, "Legal": 1, "Operational": 0, "Reputational": 0}
        return min(5, base_score + impact_bonus.get(control.business_impact, 0))
    
    def _calculate_risk_reduction(self, control: Control) -> float:
        """Calcula reducción de riesgo en EUR por implementar el control"""
        relevant_scenarios = [s for s in self.risk_scenarios if control.id in s.controls_mapping]
        total_reduction = 0
        
        for scenario in relevant_scenarios:
            # Reducción proporcional basada en mejora de madurez
            gap = control.target_maturity - control.current_maturity
            if gap > 0:
                reduction_factor = gap / 4.0  # Normalizado a 1
                scenario_reduction = scenario.annual_loss_expectancy * reduction_factor * 0.2  # 20% por control
                total_reduction += scenario_reduction
        
        return round(total_reduction, 0)
    
    def _calculate_priority_score(self, gap: int, business_crit: int, reg_pressure: int, roi: float) -> float:
        """Calcula score de prioridad multifactorial"""
        priority = (gap * 1.5) + (business_crit * 1.2) + (reg_pressure * 0.8) + min(roi, 2.0)
        return round(priority, 2)
    
    def generate_executive_dashboard(self, gap_df: pd.DataFrame) -> Dict:
        """Dashboard ejecutivo con KPIs avanzados"""
        total_controls = len(gap_df)
        controls_with_gaps = len(gap_df[gap_df["Gap"] > 0])
        
        # Métricas de cumplimiento
        max_possible_score = gap_df["Target_Maturity"].sum()
        current_score = gap_df["Current_Maturity"].sum()
        compliance_percentage = (current_score / max_possible_score) * 100
        
        # Análisis financiero
        total_implementation_cost = gap_df[gap_df["Gap"] > 0]["Implementation_Cost"].sum()
        annual_maintenance_cost = gap_df["Annual_Maintenance"].sum()
        total_risk_reduction = gap_df["Risk_Reduction_Value"].sum()
        
        # ROI del programa
        program_roi = (total_risk_reduction - total_implementation_cost) / total_implementation_cost * 100
        payback_period = total_implementation_cost / (total_risk_reduction / 12) if total_risk_reduction > 0 else float('inf')
        
        # Comparación con industria
        industry_benchmark = self.industry_benchmarks
        maturity_vs_industry = gap_df["Current_Maturity"].mean() - industry_benchmark["avg_maturity"]
        compliance_vs_industry = compliance_percentage - industry_benchmark["avg_compliance"]
        
        # Análisis de criticidad
        critical_gaps = len(gap_df[(gap_df["Criticality"] == "Critical") & (gap_df["Gap"] > 0)])
        high_priority_items = len(gap_df[gap_df["Implementation_Priority"] == "Critical"])
        
        # Distribución por departamentos
        dept_analysis = gap_df.groupby("Department").agg({
            "Gap": "sum",
            "Implementation_Cost": "sum",
            "Priority_Score": "mean"
        }).round(2)
        
        # Timeline de implementación
        effort_by_priority = gap_df.groupby("Implementation_Priority")["Effort_Days"].sum()
        
        return {
            # Métricas principales
            "compliance_percentage": round(compliance_percentage, 1),
            "maturity_score": round(gap_df["Current_Maturity"].mean(), 2),
            "total_controls": total_controls,
            "controls_with_gaps": controls_with_gaps,
            "critical_gaps": critical_gaps,
            "high_priority_items": high_priority_items,
            
            # Análisis financiero
            "total_implementation_cost": total_implementation_cost,
            "annual_maintenance_cost": annual_maintenance_cost,
            "total_risk_reduction": total_risk_reduction,
            "program_roi": round(program_roi, 1),
            "payback_period_months": round(payback_period, 1) if payback_period != float('inf') else "N/A",
            
            # Benchmarking
            "maturity_vs_industry": round(maturity_vs_industry, 2),
            "compliance_vs_industry": round(compliance_vs_industry, 1),
            "industry_benchmark": industry_benchmark,
            
            # Análisis operacional
            "department_analysis": dept_analysis.to_dict(),
            "effort_by_priority": effort_by_priority.to_dict(),
            "average_evidence_score": round(gap_df["Evidence_Score"].mean(), 2),
            
            # Riesgos
            "total_annual_exposure": sum([s.annual_loss_expectancy for s in self.risk_scenarios]),
            "residual_risk_after_implementation": round(sum([s.annual_loss_expectancy for s in self.risk_scenarios]) - total_risk_reduction, 0)
        }
    
    def create_implementation_roadmap(self, gap_df: pd.DataFrame) -> pd.DataFrame:
        """Roadmap detallado con fases y dependencias"""
        roadmap_df = gap_df[gap_df["Gap"] > 0].copy()
        roadmap_df = roadmap_df.sort_values(["Priority_Score"], ascending=False)
        
        # Asignar fases de implementación
        phases = []
        cumulative_effort = 0
        current_phase = 1
        phase_effort_limit = self.project_timeline * 20  # 20 días/mes aprox
        
        for idx, row in roadmap_df.iterrows():
            if cumulative_effort + row["Effort_Days"] > phase_effort_limit:
                current_phase += 1
                cumulative_effort = 0
                phase_effort_limit = self.project_timeline * 20  # Reset para nueva fase
            
            phases.append(f"Phase {current_phase}")
            cumulative_effort += row["Effort_Days"]
        
        roadmap_df["Implementation_Phase"] = phases
        
        # Calcular fechas estimadas
        start_dates = []
        end_dates = []
        current_date = datetime.now()
        
        for phase in roadmap_df["Implementation_Phase"]:
            phase_num = int(phase.split(" ")[1])
            start_date = current_date + timedelta(days=(phase_num - 1) * 90)  # 3 meses por fase
            end_date = start_date + timedelta(days=90)
            start_dates.append(start_date.strftime("%Y-%m-%d"))
            end_dates.append(end_date.strftime("%Y-%m-%d"))
        
        roadmap_df["Estimated_Start"] = start_dates
        roadmap_df["Estimated_End"] = end_dates
        
        # Añadir información de dependencias
        roadmap_df["Dependency_Risk"] = roadmap_df["Dependencies"].apply(
            lambda x: "High" if len(x.split(",")) > 2 else "Medium" if len(x.split(",")) > 0 else "Low"
        )
        
        return roadmap_df[[
            "Control_ID", "Control_Name", "Implementation_Priority", "Priority_Score",
            "Implementation_Phase", "Estimated_Start", "Estimated_End", 
            "Implementation_Cost", "Effort_Days", "ROI_Score", "Department",
            "Dependencies", "Dependency_Risk", "Business_Impact"
        ]]
    
    def create_risk_heat_map(self, gap_df: pd.DataFrame) -> None:
        """Crea visualizaciones separadas para mejor legibilidad"""
        
        # Gráfico 1: Mapa de Calor de Riesgos
        self._create_risk_heatmap_chart(gap_df)
        
        # Gráfico 2: Análisis Costo-ROI
        self._create_cost_roi_analysis(gap_df)
        
        # Gráfico 3: Dashboard de Madurez
        self._create_maturity_dashboard(gap_df)
        
        # Gráfico 4: Dashboard Ejecutivo
        self._create_executive_kpi_dashboard(gap_df)
    
    def _create_risk_heatmap_chart(self, gap_df: pd.DataFrame) -> None:
        """Mapa de calor de riesgos principal con alineación perfecta"""
        # Configurar figura con márgenes optimizados
        fig, ax = plt.subplots(figsize=(14, 10))
        fig.patch.set_facecolor('white')
        
        # Crear matriz de riesgos
        risk_matrix = gap_df.pivot_table(
            values="Priority_Score", 
            index="Criticality", 
            columns="Category", 
            aggfunc="mean", 
            fill_value=0
        )
        
        # Reordenar para mejor visualización
        criticality_order = ['Critical', 'High', 'Medium', 'Low']
        risk_matrix = risk_matrix.reindex([c for c in criticality_order if c in risk_matrix.index])
        
        # Crear heatmap con configuración profesional
        sns.heatmap(risk_matrix, 
                   annot=True, 
                   fmt='.1f', 
                   cmap="RdYlBu_r",
                   ax=ax,
                   square=False,
                   linewidths=1,
                   linecolor='white',
                   cbar_kws={
                       'label': 'Priority Score', 
                       'shrink': 0.8,
                       'aspect': 20,
                       'pad': 0.02
                   },
                   annot_kws={'size': 12, 'weight': 'bold'})
        
        # Configurar título y labels con espaciado perfecto
        ax.set_title(f"ISO 27001 Risk Priority Matrix\n{self.company_name}", 
                    fontsize=16, fontweight='bold', pad=25, loc='center')
        ax.set_xlabel("Control Category", fontsize=13, fontweight='semibold', labelpad=15)
        ax.set_ylabel("Criticality Level", fontsize=13, fontweight='semibold', labelpad=15)
        
        # Mejorar etiquetas de ejes
        ax.set_xticklabels(ax.get_xticklabels(), rotation=30, ha='right', fontsize=11)
        ax.set_yticklabels(ax.get_yticklabels(), rotation=0, ha='right', fontsize=11)
        
        # Añadir borde elegante
        for spine in ax.spines.values():
            spine.set_visible(True)
            spine.set_linewidth(1.5)
            spine.set_edgecolor('#333333')
        
        plt.subplots_adjust(left=0.15, bottom=0.15, right=0.92, top=0.9)
        plt.savefig(f"01_Risk_Heatmap_{self.company_name}_{datetime.now().strftime('%Y%m%d')}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white', edgecolor='none')
        plt.show()
    
    def _create_cost_roi_analysis(self, gap_df: pd.DataFrame) -> None:
        """Análisis de costo vs ROI con alineación perfecta"""
        # Configurar figura con layout óptimo
        fig = plt.figure(figsize=(18, 8))
        fig.patch.set_facecolor('white')
        
        # Crear grid layout personalizado para mejor control
        gs = fig.add_gridspec(1, 2, width_ratios=[1.2, 1], hspace=0.3, wspace=0.25,
                             left=0.08, right=0.95, top=0.85, bottom=0.15)
        
        ax1 = fig.add_subplot(gs[0, 0])
        ax2 = fig.add_subplot(gs[0, 1])
        
        scatter_data = gap_df[gap_df["Gap"] > 0]
        
        # Scatter plot Costo vs ROI con colores corporativos
        colors = {
            "Critical": "#C0392B", 
            "High": "#E67E22", 
            "Medium": "#F1C40F", 
            "Low": "#27AE60"
        }
        
        # Crear scatter plot con tamaños variables
        for priority in ["Critical", "High", "Medium", "Low"]:
            if priority in scatter_data["Implementation_Priority"].values:
                subset = scatter_data[scatter_data["Implementation_Priority"] == priority]
                scatter = ax1.scatter(subset["Implementation_Cost"], subset["ROI_Score"], 
                           label=priority, alpha=0.75, s=120, 
                           color=colors[priority], edgecolors='white', linewidth=1.5)
        
        # Configurar scatter plot
        ax1.set_xlabel("Implementation Cost (EUR)", fontsize=12, fontweight='semibold', labelpad=12)
        ax1.set_ylabel("ROI Score", fontsize=12, fontweight='semibold', labelpad=12)
        ax1.set_title("Cost vs ROI Analysis", fontsize=14, fontweight='bold', pad=20)
        
        # Mejorar leyenda
        legend = ax1.legend(title="Priority Level", bbox_to_anchor=(1.02, 1), loc='upper left',
                           frameon=True, fancybox=True, shadow=True, fontsize=10)
        legend.get_title().set_fontweight('bold')
        legend.get_title().set_fontsize(11)
        
        # Grid más sutil y profesional
        ax1.grid(True, alpha=0.3, linestyle='--', linewidth=0.7)
        ax1.set_axisbelow(True)
        
        # Formatear números en eje X
        ax1.ticklabel_format(style='plain', axis='x')
        ax1.tick_params(axis='both', which='major', labelsize=10)
        
        # Añadir línea de tendencia sutil
        if len(scatter_data) > 1:
            z = np.polyfit(scatter_data["Implementation_Cost"], scatter_data["ROI_Score"], 1)
            p = np.poly1d(z)
            ax1.plot(scatter_data["Implementation_Cost"], p(scatter_data["Implementation_Cost"]), 
                    "r--", alpha=0.4, linewidth=2, label='Trend')
        
        # Gráfico de costos por categoría mejorado
        cost_by_category = gap_df[gap_df["Gap"] > 0].groupby("Category")["Implementation_Cost"].sum()
        
        # Paleta de colores profesional
        category_colors = ['#3498DB', '#E74C3C', '#2ECC71', '#F39C12', '#9B59B6'][:len(cost_by_category)]
        
        bars = ax2.bar(range(len(cost_by_category)), cost_by_category.values, 
                      color=category_colors, alpha=0.8, edgecolor='white', linewidth=1.5)
        
        # Configurar gráfico de barras
        ax2.set_xlabel("Category", fontsize=12, fontweight='semibold', labelpad=12)
        ax2.set_ylabel("Implementation Cost (EUR)", fontsize=12, fontweight='semibold', labelpad=12)
        ax2.set_title("Implementation Cost by Category", fontsize=14, fontweight='bold', pad=20)
        ax2.set_xticks(range(len(cost_by_category)))
        ax2.set_xticklabels(cost_by_category.index, rotation=35, ha='right', fontsize=10)
        
        # Grid horizontal sutil
        ax2.grid(True, alpha=0.3, linestyle='--', linewidth=0.7, axis='y')
        ax2.set_axisbelow(True)
        
        # Añadir valores en las barras con mejor posicionamiento
        max_height = max(cost_by_category.values)
        for i, bar in enumerate(bars):
            height = bar.get_height()
            # Formatear números con separadores de miles
            formatted_value = f'€{height:,.0f}'
            ax2.text(bar.get_x() + bar.get_width()/2., height + max_height*0.01,
                    formatted_value, ha='center', va='bottom', fontsize=9, 
                    fontweight='semibold', color='#2C3E50')
        
        # Configurar spines para ambos gráficos
        for ax in [ax1, ax2]:
            for spine in ax.spines.values():
                spine.set_linewidth(1.2)
                spine.set_edgecolor('#34495E')
            ax.tick_params(colors='#2C3E50')
        
        # Título general
        fig.suptitle(f"Financial Impact Analysis - {self.company_name}", 
                    fontsize=16, fontweight='bold', y=0.95, color='#2C3E50')
        
        plt.savefig(f"02_Cost_ROI_Analysis_{self.company_name}_{datetime.now().strftime('%Y%m%d')}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white', edgecolor='none')
        plt.show()
    
    def _create_maturity_dashboard(self, gap_df: pd.DataFrame) -> None:
        """Dashboard de madurez y gaps con alineación perfecta"""
        # Configurar figura con layout profesional
        fig = plt.figure(figsize=(20, 14))
        fig.patch.set_facecolor('white')
        
        # Grid layout avanzado para control perfecto del espaciado
        gs = fig.add_gridspec(2, 2, hspace=0.35, wspace=0.25,
                             left=0.08, right=0.95, top=0.92, bottom=0.08)
        
        ax1 = fig.add_subplot(gs[0, 0])
        ax2 = fig.add_subplot(gs[0, 1])
        ax3 = fig.add_subplot(gs[1, 0])
        ax4 = fig.add_subplot(gs[1, 1])
        
        # Colores corporativos consistentes
        primary_color = '#2C3E50'
        secondary_color = '#34495E'
        accent_colors = ['#3498DB', '#E74C3C', '#2ECC71', '#F39C12', '#9B59B6']
        
        # 1. Madurez por categoría con diseño mejorado
        maturity_data = gap_df.groupby("Category")[["Current_Maturity", "Target_Maturity"]].mean()
        x_pos = np.arange(len(maturity_data.index))
        width = 0.35
        
        bars1 = ax1.bar(x_pos - width/2, maturity_data["Current_Maturity"], width, 
                       label="Current Maturity", color="#3498DB", alpha=0.85, 
                       edgecolor='white', linewidth=1.5)
        bars2 = ax1.bar(x_pos + width/2, maturity_data["Target_Maturity"], width, 
                       label="Target Maturity", color="#E74C3C", alpha=0.85,
                       edgecolor='white', linewidth=1.5)
        
        ax1.set_xlabel("Control Category", fontsize=12, fontweight='semibold', labelpad=15)
        ax1.set_ylabel("Maturity Level (0-4)", fontsize=12, fontweight='semibold', labelpad=15)
        ax1.set_title("Current vs Target Maturity by Category", fontsize=14, fontweight='bold', pad=20)
        ax1.set_xticks(x_pos)
        ax1.set_xticklabels(maturity_data.index, rotation=25, ha='right', fontsize=11)
        
        # Leyenda mejorada
        legend1 = ax1.legend(loc='upper left', frameon=True, fancybox=True, shadow=True, fontsize=11)
        legend1.get_frame().set_facecolor('white')
        legend1.get_frame().set_alpha(0.9)
        
        ax1.grid(True, alpha=0.3, linestyle='--', linewidth=0.7, axis='y')
        ax1.set_axisbelow(True)
        ax1.set_ylim(0, 4.5)
        
        # Añadir valores en las barras con mejor posicionamiento
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + 0.08,
                        f'{height:.1f}', ha='center', va='bottom', fontsize=10, 
                        fontweight='bold', color=primary_color)
        
        # 2. Distribución de gaps mejorada
        gap_counts = gap_df["Gap"].value_counts().sort_index()
        gap_labels = [f'Gap {i}' for i in gap_counts.index]
        colors_gap = ['#27AE60', '#F1C40F', '#E67E22', '#C0392B', '#8E44AD'][:len(gap_counts)]
        
        bars = ax2.bar(gap_counts.index, gap_counts.values, color=colors_gap, alpha=0.85,
                      edgecolor='white', linewidth=1.5)
        
        ax2.set_xlabel("Gap Size (Target - Current)", fontsize=12, fontweight='semibold', labelpad=15)
        ax2.set_ylabel("Number of Controls", fontsize=12, fontweight='semibold', labelpad=15)
        ax2.set_title("Distribution of Control Gaps", fontsize=14, fontweight='bold', pad=20)
        ax2.grid(True, alpha=0.3, linestyle='--', linewidth=0.7, axis='y')
        ax2.set_axisbelow(True)
        
        # Añadir valores en las barras
        max_count = max(gap_counts.values)
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + max_count*0.02,
                    f'{int(height)}', ha='center', va='bottom', fontsize=11, 
                    fontweight='bold', color=primary_color)
        
        # 3. Esfuerzo por prioridad - diseño elegante
        effort_data = gap_df[gap_df["Gap"] > 0].groupby("Implementation_Priority")["Effort_Days"].sum()
        if len(effort_data) > 0:
            # Colores específicos para prioridades
            priority_colors = {
                'Critical': '#C0392B',
                'High': '#E67E22', 
                'Medium': '#F1C40F',
                'Low': '#27AE60'
            }
            colors = [priority_colors.get(priority, '#95A5A6') for priority in effort_data.index]
            
            wedges, texts, autotexts = ax3.pie(effort_data.values, labels=effort_data.index, 
                                              autopct='%1.1f%%', startangle=90, colors=colors,
                                              explode=[0.05 if p == 'Critical' else 0 for p in effort_data.index],
                                              wedgeprops=dict(width=0.8, edgecolor='white', linewidth=2))
            
            ax3.set_title("Implementation Effort Distribution", fontsize=14, fontweight='bold', pad=20)
            
            # Mejorar texto del pie chart
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(11)
            
            for text in texts:
                text.set_fontsize(11)
                text.set_fontweight('semibold')
        
        # 4. Compliance score por departamento mejorado
        dept_compliance = gap_df.groupby("Department").agg({
            "Current_Maturity": "mean",
            "Target_Maturity": "mean"
        })
        dept_compliance["Compliance_Score"] = (dept_compliance["Current_Maturity"] / 
                                             dept_compliance["Target_Maturity"] * 100)
        
        # Ordenar por compliance score
        dept_compliance = dept_compliance.sort_values("Compliance_Score", ascending=True)
        
        # Colores basados en performance
        colors_dept = ['#E74C3C' if score < 50 else '#F39C12' if score < 75 else '#27AE60' 
                      for score in dept_compliance["Compliance_Score"]]
        
        bars = ax4.barh(range(len(dept_compliance)), dept_compliance["Compliance_Score"], 
                       color=colors_dept, alpha=0.85, edgecolor='white', linewidth=1.5)
        
        ax4.set_xlabel("Compliance Score (%)", fontsize=12, fontweight='semibold', labelpad=15)
        ax4.set_ylabel("Department", fontsize=12, fontweight='semibold', labelpad=15)
        ax4.set_title("Compliance Score by Department", fontsize=14, fontweight='bold', pad=20)
        ax4.set_yticks(range(len(dept_compliance)))
        ax4.set_yticklabels(dept_compliance.index, fontsize=10)
        ax4.grid(True, alpha=0.3, linestyle='--', linewidth=0.7, axis='x')
        ax4.set_axisbelow(True)
        ax4.set_xlim(0, 105)
        
        # Añadir valores en las barras horizontales
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax4.text(width + 1.5, bar.get_y() + bar.get_height()/2,
                    f'{width:.1f}%', ha='left', va='center', fontsize=10,
                    fontweight='bold', color=primary_color)
        
        # Configurar spines para todos los gráficos
        for ax in [ax1, ax2, ax3, ax4]:
            if ax != ax3:  # Skip pie chart
                for spine in ax.spines.values():
                    spine.set_linewidth(1.2)
                    spine.set_edgecolor(secondary_color)
                ax.tick_params(colors=primary_color, labelsize=10)
        
        # Título general elegante
        fig.suptitle(f"ISO 27001 Maturity & Gap Analysis Dashboard\n{self.company_name}", 
                    fontsize=18, fontweight='bold', y=0.97, color=primary_color)
        
        plt.savefig(f"03_Maturity_Dashboard_{self.company_name}_{datetime.now().strftime('%Y%m%d')}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white', edgecolor='none')
        plt.show()
    
    def _create_executive_kpi_dashboard(self, gap_df: pd.DataFrame) -> None:
        """Dashboard de KPIs ejecutivos con diseño corporativo premium"""
        dashboard = self.generate_executive_dashboard(gap_df)
        
        # Configurar figura con diseño ejecutivo
        fig = plt.figure(figsize=(20, 14))
        fig.patch.set_facecolor('#F8F9FA')
        
        # Grid layout sofisticado para diseño ejecutivo
        gs = fig.add_gridspec(4, 6, hspace=0.4, wspace=0.3,
                             left=0.06, right=0.96, top=0.93, bottom=0.08)
        
        # Colores corporativos premium
        primary_color = '#2C3E50'
        secondary_color = '#34495E'
        accent_blue = '#3498DB'
        accent_green = '#27AE60'
        accent_red = '#E74C3C'
        accent_orange = '#F39C12'
        accent_purple = '#9B59B6'
        
        # KPI principal: Gauge de Compliance - Tamaño más grande
        ax_main = fig.add_subplot(gs[0:2, 0:3])
        self._create_premium_gauge_chart(ax_main, dashboard['compliance_percentage'], 
                                        "Overall ISO 27001 Compliance", "%", primary_color)
        
        # Tarjetas de métricas ejecutivas - Fila superior
        ax_roi = fig.add_subplot(gs[0, 3])
        roi_color = accent_green if dashboard['program_roi'] > 0 else accent_red
        self._create_executive_metric_card(ax_roi, f"{dashboard['program_roi']:.1f}%", 
                                         "Program ROI", roi_color)
        
        ax_cost = fig.add_subplot(gs[0, 4])
        self._create_executive_metric_card(ax_cost, f"€{dashboard['total_implementation_cost']/1000:.0f}K", 
                                         "Investment Required", accent_blue)
        
        ax_risk = fig.add_subplot(gs[0, 5])
        self._create_executive_metric_card(ax_risk, f"€{dashboard['total_risk_reduction']/1000:.0f}K", 
                                         "Annual Risk Reduction", accent_purple)
        
        # Tarjetas de métricas secundarias - Segunda fila
        ax_maturity = fig.add_subplot(gs[1, 3])
        self._create_executive_metric_card(ax_maturity, f"{dashboard['maturity_score']:.1f}/4.0", 
                                         "Avg Maturity", accent_orange)
        
        ax_gaps = fig.add_subplot(gs[1, 4])
        self._create_executive_metric_card(ax_gaps, f"{dashboard['controls_with_gaps']}", 
                                         "Controls with Gaps", accent_red)
        
        ax_payback = fig.add_subplot(gs[1, 5])
        payback_text = f"{dashboard['payback_period_months']:.1f}m" if dashboard['payback_period_months'] != "N/A" else "N/A"
        self._create_executive_metric_card(ax_payback, payback_text, 
                                         "Payback Period", secondary_color)
        
        # Gráfico de benchmark vs industria - Más prominente
        ax_benchmark = fig.add_subplot(gs[2, 0:3])
        categories = ['Maturity Score', 'Compliance %']
        our_values = [dashboard['maturity_score'], dashboard['compliance_percentage']]
        industry_values = [dashboard['industry_benchmark']['avg_maturity'], 
                          dashboard['industry_benchmark']['avg_compliance']]
        
        x = np.arange(len(categories))
        width = 0.35
        
        bars1 = ax_benchmark.bar(x - width/2, our_values, width, 
                                label=f'{self.company_name}', color=accent_blue, 
                                alpha=0.9, edgecolor='white', linewidth=2)
        bars2 = ax_benchmark.bar(x + width/2, industry_values, width, 
                                label=f'{self.industry} Industry Average', 
                                color='#BDC3C7', alpha=0.8, edgecolor='white', linewidth=2)
        
        ax_benchmark.set_ylabel('Score', fontsize=12, fontweight='semibold')
        ax_benchmark.set_title('Performance vs Industry Benchmark', 
                              fontsize=14, fontweight='bold', color=primary_color, pad=20)
        ax_benchmark.set_xticks(x)
        ax_benchmark.set_xticklabels(categories, fontsize=11, fontweight='semibold')
        
        # Leyenda mejorada
        legend = ax_benchmark.legend(loc='upper right', frameon=True, fancybox=True, 
                                   shadow=True, fontsize=11)
        legend.get_frame().set_facecolor('white')
        legend.get_frame().set_alpha(0.95)
        
        ax_benchmark.grid(True, alpha=0.3, linestyle='--', linewidth=0.7, axis='y')
        ax_benchmark.set_axisbelow(True)
        
        # Añadir valores en las barras con indicadores de mejora
        for i, (bar1, bar2) in enumerate(zip(bars1, bars2)):
            height1, height2 = bar1.get_height(), bar2.get_height()
            
            # Mostrar valores
            ax_benchmark.text(bar1.get_x() + bar1.get_width()/2., height1 + max(our_values)*0.02,
                            f'{height1:.1f}', ha='center', va='bottom', fontsize=10, 
                            fontweight='bold', color=primary_color)
            ax_benchmark.text(bar2.get_x() + bar2.get_width()/2., height2 + max(industry_values)*0.02,
                            f'{height2:.1f}', ha='center', va='bottom', fontsize=10, 
                            fontweight='bold', color=secondary_color)
            
            # Indicador de performance vs industria
            diff = height1 - height2
            arrow_color = accent_green if diff > 0 else accent_red
            arrow_symbol = '↑' if diff > 0 else '↓'
            ax_benchmark.text(x[i], max(height1, height2) + max(our_values)*0.08,
                            f'{arrow_symbol} {abs(diff):.1f}', ha='center', va='bottom',
                            fontsize=12, fontweight='bold', color=arrow_color)
        
        # Distribución de riesgos por categoría
        ax_risk_dist = fig.add_subplot(gs[2, 3:6])
        risk_by_category = gap_df.groupby("Category")["Priority_Score"].mean().sort_values(ascending=False)
        
        colors_risk = [accent_red, accent_orange, accent_blue, accent_green, accent_purple][:len(risk_by_category)]
        bars = ax_risk_dist.bar(range(len(risk_by_category)), risk_by_category.values,
                               color=colors_risk, alpha=0.85, edgecolor='white', linewidth=1.5)
        
        ax_risk_dist.set_xlabel('Control Category', fontsize=12, fontweight='semibold')
        ax_risk_dist.set_ylabel('Average Priority Score', fontsize=12, fontweight='semibold')
        ax_risk_dist.set_title('Risk Priority by Category', fontsize=14, fontweight='bold', 
                              color=primary_color, pad=20)
        ax_risk_dist.set_xticks(range(len(risk_by_category)))
        ax_risk_dist.set_xticklabels(risk_by_category.index, rotation=25, ha='right', fontsize=10)
        ax_risk_dist.grid(True, alpha=0.3, linestyle='--', linewidth=0.7, axis='y')
        ax_risk_dist.set_axisbelow(True)
        
        # Valores en barras de riesgo
        for bar in bars:
            height = bar.get_height()
            ax_risk_dist.text(bar.get_x() + bar.get_width()/2., height + height*0.02,
                            f'{height:.1f}', ha='center', va='bottom', fontsize=10, 
                            fontweight='bold', color=primary_color)
        
        # Timeline de implementación con diseño premium
        ax_timeline = fig.add_subplot(gs[3, 0:6])
        phases = ['Phase 1\n(Immediate)', 'Phase 2\n(0-6 months)', 'Phase 3\n(6-12 months)', 'Phase 4\n(12-18 months)']
        efforts = [35, 30, 25, 10]  # Porcentajes realistas
        
        # Colores degradados para timeline
        timeline_colors = ['#E74C3C', '#F39C12', '#F1C40F', '#27AE60']
        bars = ax_timeline.bar(phases, efforts, color=timeline_colors, alpha=0.85,
                              edgecolor='white', linewidth=2)
        
        ax_timeline.set_ylabel('Implementation Effort (%)', fontsize=12, fontweight='semibold')
        ax_timeline.set_title('Implementation Roadmap Timeline', fontsize=14, fontweight='bold', 
                             color=primary_color, pad=20)
        ax_timeline.grid(True, alpha=0.3, linestyle='--', linewidth=0.7, axis='y')
        ax_timeline.set_axisbelow(True)
        ax_timeline.set_ylim(0, max(efforts) * 1.15)
        
        # Valores y descripciones en timeline
        descriptions = ['Critical Controls', 'High Priority', 'Medium Priority', 'Low Priority']
        for i, (bar, desc) in enumerate(zip(bars, descriptions)):
            height = bar.get_height()
            # Porcentaje en la barra
            ax_timeline.text(bar.get_x() + bar.get_width()/2., height/2,
                           f'{height}%', ha='center', va='center', fontsize=12,
                           fontweight='bold', color='white')
            # Descripción debajo
            ax_timeline.text(bar.get_x() + bar.get_width()/2., -max(efforts)*0.08,
                           desc, ha='center', va='top', fontsize=9,
                           fontweight='semibold', color=secondary_color)
        
        # Configurar spines para todos los gráficos
        for ax in [ax_benchmark, ax_risk_dist, ax_timeline]:
            for spine in ax.spines.values():
                spine.set_linewidth(1.2)
                spine.set_edgecolor(secondary_color)
            ax.tick_params(colors=primary_color, labelsize=10)
        
        # Título principal con diseño ejecutivo
        fig.suptitle(f"Executive Dashboard - ISO 27001 Security Posture\n{self.company_name}", 
                    fontsize=20, fontweight='bold', y=0.97, color=primary_color)
        
        # Añadir fecha y ID de evaluación
        fig.text(0.95, 0.02, f"Assessment ID: {self.assessment_id} | {datetime.now().strftime('%d/%m/%Y')}", 
                ha='right', va='bottom', fontsize=9, color=secondary_color, alpha=0.8)
        
        plt.savefig(f"04_Executive_Dashboard_{self.company_name}_{datetime.now().strftime('%Y%m%d')}.png", 
                   dpi=300, bbox_inches='tight', facecolor='#F8F9FA', edgecolor='none')
        plt.show()
    
    def _create_premium_gauge_chart(self, ax, value, title, unit, color):
        """Crea un gauge chart premium para el dashboard ejecutivo"""
        # Configuración del gauge
        theta_max = np.pi
        theta = np.linspace(0, theta_max, 100)
        
        # Crear múltiples anillos para efecto premium
        ax.fill_between(theta, 0.7, 1.0, color='#ECF0F1', alpha=0.4)
        ax.fill_between(theta, 0.75, 0.95, color='#BDC3C7', alpha=0.3)
        
        # Llenar hasta el valor actual con gradiente
        value_theta = np.linspace(0, theta_max * (value/100), int(value*2))
        if len(value_theta) > 0:
            if value < 50:
                gauge_color = '#E74C3C'
            elif value < 75:
                gauge_color = '#F39C12'
            else:
                gauge_color = '#27AE60'
            
            ax.fill_between(value_theta, 0.75, 0.95, color=gauge_color, alpha=0.9)
        
        # Añadir marcas de escala
        for i in range(0, 101, 25):
            angle = theta_max * (i/100)
            ax.plot([angle, angle], [0.7, 0.75], color='#34495E', linewidth=2)
            ax.text(angle, 0.65, f'{i}', ha='center', va='center', 
                   fontsize=9, fontweight='bold', color='#2C3E50')
        
        # Indicador de valor
        value_angle = theta_max * (value/100)
        ax.plot([value_angle, value_angle], [0.75, 0.95], color='#2C3E50', linewidth=4)
        ax.scatter([value_angle], [0.85], s=100, color='#2C3E50', zorder=5)
        
        # Texto central principal
        ax.text(theta_max/2, 0.45, f"{value:.1f}{unit}", ha='center', va='center', 
               fontsize=28, fontweight='bold', color=color)
        ax.text(theta_max/2, 0.25, title, ha='center', va='center', 
               fontsize=13, fontweight='bold', color='#2C3E50')
        
        # Configuración del área
        ax.set_xlim(0, theta_max)
        ax.set_ylim(0, 1.1)
        ax.set_aspect('equal')
        ax.axis('off')
        
        # Marco decorativo
        circle = plt.Circle((theta_max/2, 0.5), 0.55, fill=False, 
                           edgecolor=color, linewidth=3, alpha=0.7)
        ax.add_patch(circle)
    
    def _create_executive_metric_card(self, ax, value, label, color):
        """Crea tarjetas de métricas con diseño ejecutivo premium"""
        # Fondo de la tarjeta
        ax.add_patch(plt.Rectangle((0.05, 0.1), 0.9, 0.8, 
                                  fill=True, facecolor='white', 
                                  edgecolor=color, linewidth=3, alpha=0.95))
        
        # Valor principal
        ax.text(0.5, 0.65, value, ha='center', va='center', 
               fontsize=18, fontweight='bold', color=color, transform=ax.transAxes)
        
        # Label
        ax.text(0.5, 0.35, label, ha='center', va='center', 
               fontsize=11, fontweight='bold', color='#2C3E50', transform=ax.transAxes)
        
        # Línea decorativa
        ax.plot([0.2, 0.8], [0.5, 0.5], color=color, linewidth=2, alpha=0.6, transform=ax.transAxes)
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
    
    def generate_regulatory_compliance_report(self, gap_df: pd.DataFrame) -> pd.DataFrame:
        """Reporte de cumplimiento regulatorio específico"""
        regulatory_data = []
        
        for regulation, control_ids in self.regulatory_requirements.items():
            relevant_controls = gap_df[gap_df["Control_ID"].isin(control_ids)]
            
            if len(relevant_controls) > 0:
                compliance_score = (relevant_controls["Current_Maturity"].sum() / 
                                  (relevant_controls["Target_Maturity"].sum())) * 100
                
                gaps_count = len(relevant_controls[relevant_controls["Gap"] > 0])
                implementation_cost = relevant_controls[relevant_controls["Gap"] > 0]["Implementation_Cost"].sum()
                
                regulatory_data.append({
                    "Regulation": regulation,
                    "Total_Controls": len(relevant_controls),
                    "Controls_with_Gaps": gaps_count,
                    "Compliance_Score": round(compliance_score, 1),
                    "Implementation_Cost": implementation_cost,
                    "High_Priority_Controls": len(relevant_controls[relevant_controls["Implementation_Priority"] == "Critical"]),
                    "Status": "Non-Compliant" if compliance_score < 80 else "Partially Compliant" if compliance_score < 95 else "Compliant"
                })
        
        return pd.DataFrame(regulatory_data)
    
    def export_enterprise_results(self, gap_df: pd.DataFrame, dashboard: Dict, 
                                roadmap_df: pd.DataFrame, regulatory_df: pd.DataFrame):
        """Exporta resultados en formato empresarial"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ISO27001_Enterprise_Analysis_{self.company_name}_{timestamp}.xlsx"
        
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            # Hoja 1: Resumen Ejecutivo
            executive_summary = pd.DataFrame([{
                "Metric": k.replace("_", " ").title(),
                "Value": v
            } for k, v in dashboard.items() if not isinstance(v, dict)])
            executive_summary.to_excel(writer, sheet_name="Executive Summary", index=False)
            
            # Hoja 2: Gap Analysis Completo
            gap_df.to_excel(writer, sheet_name="Gap Analysis", index=False)
            
            # Hoja 3: Implementation Roadmap
            roadmap_df.to_excel(writer, sheet_name="Implementation Roadmap", index=False)
            
            # Hoja 4: Regulatory Compliance
            regulatory_df.to_excel(writer, sheet_name="Regulatory Compliance", index=False)
            
            # Hoja 5: Risk Scenarios
            risk_summary = pd.DataFrame([{
                "Risk_ID": r.id,
                "Risk_Name": r.name,
                "Threat_Actor": r.threat_actor,
                "Likelihood": r.likelihood,
                "Impact": r.impact,
                "Inherent_Risk": r.inherent_risk,
                "Annual_Loss_Expectancy": r.annual_loss_expectancy,
                "Key_Controls": ", ".join(r.controls_mapping[:3])
            } for r in self.risk_scenarios])
            risk_summary.to_excel(writer, sheet_name="Risk Scenarios", index=False)
            
            # Hoja 6: Department Analysis
            dept_df = gap_df.groupby("Department").agg({
                "Gap": "sum",
                "Implementation_Cost": "sum",
                "Effort_Days": "sum",
                "Priority_Score": "mean",
                "Control_ID": "count"
            }).round(2)
            dept_df.columns = ["Total_Gaps", "Total_Cost", "Total_Effort", "Avg_Priority", "Controls_Count"]
            dept_df.to_excel(writer, sheet_name="Department Analysis")
        
        print(f"✅ Resultados exportados: {filename}")
        return filename
    
    def run_enterprise_analysis(self):
        """Ejecuta análisis empresarial completo"""
        print("="*80)
        print(f"🏢 ANÁLISIS EMPRESARIAL ISO 27001:2022 - {self.company_name}")
        print(f"📊 Industria: {self.industry} | Empleados: {self.employee_count}")
        print(f"🔍 ID Evaluación: {self.assessment_id}")
        print(f"📅 Fecha: {self.assessment_date.strftime('%d/%m/%Y %H:%M')}")
        print("="*80)
        
        # 1. Análisis de gaps comprehensive
        print("\n🔍 1. EJECUTANDO ANÁLISIS DE GAPS...")
        gap_df = self.calculate_comprehensive_gaps()
        
        # 2. Dashboard ejecutivo
        print("📊 2. GENERANDO DASHBOARD EJECUTIVO...")
        dashboard = self.generate_executive_dashboard(gap_df)
        
        # 3. Roadmap de implementación
        print("🗺️ 3. CREANDO ROADMAP DE IMPLEMENTACIÓN...")
        roadmap_df = self.create_implementation_roadmap(gap_df)
        
        # 4. Análisis regulatorio
        print("⚖️ 4. ANÁLISIS DE CUMPLIMIENTO REGULATORIO...")
        regulatory_df = self.generate_regulatory_compliance_report(gap_df)
        
        # 5. Visualizaciones mejoradas
        print("📈 5. GENERANDO VISUALIZACIONES...")
        self.create_risk_heat_map(gap_df)
        
        # 6. Exportar resultados
        print("💾 6. EXPORTANDO RESULTADOS...")
        filename = self.export_enterprise_results(gap_df, dashboard, roadmap_df, regulatory_df)
        
        # 7. Mostrar resumen ejecutivo
        self._display_executive_summary(dashboard, regulatory_df)
        
        print(f"\n✅ ANÁLISIS COMPLETADO PARA {self.company_name}")
        print(f"📁 Archivo Excel generado: {filename}")
        print("📈 Gráficos generados:")
        print("   01_Risk_Heatmap_[company]_[date].png")
        print("   02_Cost_ROI_Analysis_[company]_[date].png") 
        print("   03_Maturity_Dashboard_[company]_[date].png")
        print("   04_Executive_Dashboard_[company]_[date].png")
        print("="*80)
        
        return gap_df, dashboard, roadmap_df, regulatory_df
    
    def _display_executive_summary(self, dashboard: Dict, regulatory_df: pd.DataFrame):
        """Muestra resumen ejecutivo en consola"""
        print("\n" + "="*60)
        print("📋 RESUMEN EJECUTIVO PARA DIRECCIÓN")
        print("="*60)
        
        print(f"""
🏢 EMPRESA: {self.company_name}
🏭 SECTOR: {self.industry}
📅 FECHA: {datetime.now().strftime('%d/%m/%Y')}

📊 ESTADO ACTUAL ISO 27001:
• Nivel de Cumplimiento: {dashboard['compliance_percentage']}%
• Madurez Promedio: {dashboard['maturity_score']}/4.0
• Controles con Brechas: {dashboard['controls_with_gaps']}/{dashboard['total_controls']}
• Riesgos Críticos: {dashboard['critical_gaps']}

💰 ANÁLISIS FINANCIERO:
• Inversión Requerida: €{dashboard['total_implementation_cost']:,}
• ROI del Programa: {dashboard['program_roi']}%
• Período de Retorno: {dashboard['payback_period_months']} meses
• Reducción de Riesgo: €{dashboard['total_risk_reduction']:,}/año

📈 VS. INDUSTRIA ({self.industry}):
• Madurez: {'+' if dashboard['maturity_vs_industry'] >= 0 else ''}{dashboard['maturity_vs_industry']:.1f} puntos
• Cumplimiento: {'+' if dashboard['compliance_vs_industry'] >= 0 else ''}{dashboard['compliance_vs_industry']:.1f}%

⚖️ CUMPLIMIENTO REGULATORIO:""")
        
        for _, row in regulatory_df.iterrows():
            print(f"• {row['Regulation']}: {row['Compliance_Score']}% ({row['Status']})")
        
        print(f"""
🎯 RECOMENDACIONES CLAVE:
1. Priorizar {dashboard['high_priority_items']} controles críticos
2. Asignar presupuesto de €{dashboard['total_implementation_cost']:,} 
3. Implementación en {self.project_timeline} meses
4. Revisión trimestral de progreso
5. Preparación para auditoría externa

📞 PRÓXIMOS PASOS:
• Aprobación ejecutiva del roadmap
• Asignación de recursos y responsables  
• Inicio Fase 1 de implementación
• Contratación de consultoría especializada (recomendado)
        """)

def main():
    """Función principal para demostración empresarial"""
    
    # Configuración de empresa ejemplo - Caso ficticio
    company_config = {
        "name": "TechSecure Solutions",
        "industry": "Technology", 
        "employees": 150
    }
    
    print("🚀 INICIANDO DEMO EMPRESARIAL - ISO 27001 GAP ANALYSIS")
    print("="*60)
    
    # Crear instancia del analizador
    analyzer = ISO27001EnterpriseAnalysis(
        company_name=company_config["name"],
        industry=company_config["industry"],
        employee_count=company_config["employees"]
    )
    
    # Ejecutar análisis completo
    gap_results, dashboard, roadmap, regulatory = analyzer.run_enterprise_analysis()
    
    # Mostrar ejemplos de uso avanzado
    print("\n" + "="*60)
    print("🔬 CAPACIDADES TÉCNICAS DEMOSTRADAS")
    print("="*60)
    print("""
✅ COMPETENCIAS GRC AVANZADAS:
• Marco completo ISO 27001:2022 (40+ controles)
• Metodología de risk assessment cuantitativo
• Análisis costo-beneficio y ROI
• Roadmap de implementación con dependencias
• Benchmarking vs. industria
• Mapeo regulatorio (GDPR, NIS2, SOX, PCI-DSS)

✅ HABILIDADES TÉCNICAS:
• Automatización con Python avanzado
• Análisis de datos multidimensional
• Visualizaciones profesionales
• Generación de reportes ejecutivos
• Gestión de evidencias y auditoría

✅ CAPACIDADES DE GESTIÓN:
• Priorización multifactorial
• Gestión de presupuestos y recursos
• Timeline y planning de proyectos
• Comunicación a nivel C-Suite
• Enfoque basado en riesgos

💼 VALOR EMPRESARIAL:
• Herramienta lista para uso inmediato
• Metodología probada y escalable
• Reducción de tiempo de consultoría
• Framework para clientes empresariales
• Diferenciación competitiva en el mercado
    """)

if __name__ == "__main__":
    main()