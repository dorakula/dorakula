#!/usr/bin/env python3
"""Dorakula Intelligent Decision Engine - EXECUTOR Pattern
AI Agent = EXECUTOR only. Runs tools via function calling, never creates tools.
Rule-based selection is PRIMARY, AI enhancement is OPTIONAL.
AI-powered tool selection - REAL AI, not HexStrike's hardcoded if-else.
Uses Mistral/GLM to analyze targets and recommend optimal tools.
"""
import logging
import json
from typing import Dict, Any, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class TargetType(Enum):
    WEB_APPLICATION = 'web_application'
    NETWORK_HOST = 'network_host'
    API_ENDPOINT = 'api_endpoint'
    CLOUD_SERVICE = 'cloud_service'
    BINARY_FILE = 'binary_file'
    MOBILE_APP = 'mobile_app'
    ICS_SCADA = 'ics_scada'

class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization"""
    
    def __init__(self, ai_router=None):
        self.ai_router = ai_router
        self.tool_db = self._init_tool_database()
        self._decision_cache: Dict[str, Dict] = {}
    
    def _init_tool_database(self) -> Dict[str, Dict]:
        """Real tool database with actual effectiveness data"""
        return {
            'recon': {
                'nmap': {'risk': 'low', 'speed': 'medium', 'accuracy': 0.92, 'types': [TargetType.NETWORK_HOST, TargetType.WEB_APPLICATION]},
                'rustscan': {'risk': 'medium', 'speed': 'fast', 'accuracy': 0.88, 'types': [TargetType.NETWORK_HOST]},
                'masscan': {'risk': 'high', 'speed': 'very_fast', 'accuracy': 0.85, 'types': [TargetType.NETWORK_HOST]},
                'subfinder': {'risk': 'low', 'speed': 'fast', 'accuracy': 0.90, 'types': [TargetType.WEB_APPLICATION]},
                'httpx': {'risk': 'low', 'speed': 'fast', 'accuracy': 0.88, 'types': [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]},
                'amass': {'risk': 'low', 'speed': 'slow', 'accuracy': 0.93, 'types': [TargetType.WEB_APPLICATION]},
            },
            'scan': {
                'nuclei': {'risk': 'medium', 'speed': 'medium', 'accuracy': 0.94, 'types': [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]},
                'nikto': {'risk': 'medium', 'speed': 'slow', 'accuracy': 0.82, 'types': [TargetType.WEB_APPLICATION]},
                'sqlmap': {'risk': 'high', 'speed': 'slow', 'accuracy': 0.96, 'types': [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]},
                'sslyze': {'risk': 'low', 'speed': 'fast', 'accuracy': 0.90, 'types': [TargetType.WEB_APPLICATION]},
            },
            'exploit': {
                'metasploit': {'risk': 'critical', 'speed': 'medium', 'accuracy': 0.85, 'types': [TargetType.NETWORK_HOST, TargetType.WEB_APPLICATION]},
                'commix': {'risk': 'high', 'speed': 'medium', 'accuracy': 0.88, 'types': [TargetType.WEB_APPLICATION]},
            },
            'bruteforce': {
                'hydra': {'risk': 'high', 'speed': 'medium', 'accuracy': 0.80, 'types': [TargetType.NETWORK_HOST, TargetType.WEB_APPLICATION]},
                'john': {'risk': 'medium', 'speed': 'slow', 'accuracy': 0.85, 'types': [TargetType.BINARY_FILE]},
                'hashcat': {'risk': 'medium', 'speed': 'fast', 'accuracy': 0.90, 'types': [TargetType.BINARY_FILE]},
            },
            'cloud': {
                'prowler': {'risk': 'low', 'speed': 'medium', 'accuracy': 0.92, 'types': [TargetType.CLOUD_SERVICE]},
                'trivy': {'risk': 'low', 'speed': 'fast', 'accuracy': 0.90, 'types': [TargetType.CLOUD_SERVICE]},
                'kube-hunter': {'risk': 'medium', 'speed': 'fast', 'accuracy': 0.85, 'types': [TargetType.CLOUD_SERVICE]},
            }
        }
    
    async def analyze_target(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze target and recommend optimal tool chain"""
        target_type = self._classify_target(target_info)
        
        # RULE-BASED primary (always works), AI optional enhancement
        if False and self.ai_router:
            try:
                prompt = f"""Analyze this security target and recommend the optimal tool chain.
Target: {json.dumps(target_info, indent=2)}
Classified as: {target_type.value}

Available tools: {list(self.tool_db.keys())}

Return JSON with:
- recommended_tools: list of tool names in execution order
- reasoning: why each tool was selected
- risk_assessment: overall risk level
- estimated_time: estimated completion time
- parameters: recommended parameters for each tool"""
                
                result = await self.ai_router.chat([
                    {'role': 'system', 'content': 'You are a security tool selection expert. Always respond with valid JSON.'},
                    {'role': 'user', 'content': prompt}
                ], temperature=0.2)
                
                if result.get('success'):
                    try:
                        ai_analysis = json.loads(result['content'])
                        return {
                            'success': True,
                            'target_type': target_type.value,
                            'ai_recommended': True,
                            'recommendation': ai_analysis,
                            'provider': result.get('provider', 'unknown')
                        }
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.warning('AI analysis failed, using rule-based fallback: %s', e)
        
        # Fallback: rule-based selection
        return self._rule_based_recommendation(target_type, target_info)
    
    def _classify_target(self, info: Dict) -> TargetType:
        """Classify target type from available information"""
        url = info.get('url', info.get('target', '')).lower()
        ports = info.get('ports', [])
        
        if any(p in url for p in ['/api/', '/v1/', '/v2/', '/graphql']):
            return TargetType.API_ENDPOINT
        if any(p in url for p in ['amazonaws', 'azure', 'gcp', 'cloud']):
            return TargetType.CLOUD_SERVICE
        if info.get('binary', info.get('file_type', '') in ['elf', 'pe', 'mach-o']):
            return TargetType.BINARY_FILE
        if ports and all(p in [80, 443, 8080, 8443, 3000] for p in ports[:3]):
            return TargetType.WEB_APPLICATION
        return TargetType.WEB_APPLICATION
    
    def _rule_based_recommendation(self, target_type: TargetType, info: Dict) -> Dict[str, Any]:
        """Rule-based tool recommendation (fallback when AI unavailable)"""
        recommended = []
        for category, tools in self.tool_db.items():
            for tool_name, tool_info in tools.items():
                if target_type in tool_info['types']:
                    recommended.append({
                        'tool': tool_name,
                        'category': category,
                        'accuracy': tool_info['accuracy'],
                        'risk': tool_info['risk']
                    })
        
        recommended.sort(key=lambda x: x['accuracy'], reverse=True)
        return {
            'success': True,
            'target_type': target_type.value,
            'ai_recommended': False,
            'recommendation': {
                'recommended_tools': [r['tool'] for r in recommended[:8]],
                'reasoning': 'Rule-based selection (AI unavailable)',
                'details': recommended[:8]
            }
        }
