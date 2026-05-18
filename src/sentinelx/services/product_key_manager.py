"""
Product Key Activation System for SentinelX
Manages license activation, trial period, and key validation with plan support.
"""

import json
import hashlib
import secrets
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class SubscriptionPlan(Enum):
    """Available subscription plans."""
    MONTHLY = ("monthly", "M", 30)
    HALF_YEARLY = ("half-yearly", "H", 180)
    ANNUAL = ("annual", "A", 365)
    
    def __init__(self, display_name: str, key_code: str, days: int):
        self.display_name = display_name
        self.key_code = key_code
        self.days = days


@dataclass
class ActivationStatus:
    """Current activation status of the system."""
    is_activated: bool
    product_key: Optional[str] = None
    activation_date: Optional[str] = None
    trial_days_remaining: int = 0
    is_trial: bool = False
    expiration_date: Optional[str] = None
    plan: Optional[str] = None  # 'monthly', 'half-yearly', 'annual'
    plan_days_remaining: int = 0


class ProductKeyManager:
    """Manages product key validation and activation."""
    
    TRIAL_PERIOD_DAYS = 30
    KEY_FORMAT = "SENT-{code}{segment1}-{segment2}-{segment3}"  # SENT-M/H/AXXX-XXXX-XXXX
    
    def __init__(self):
        self.activation_file = Path('config/activation.json')
        self.status = self._load_activation_status()
    
    def _generate_segment(self, length: int = 4) -> str:
        """Generate a random alphanumeric segment."""
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def _calculate_checksum(self, key_data: str) -> str:
        """Calculate checksum for key validation."""
        return hashlib.sha256(key_data.encode()).hexdigest()[:8].upper()
    
    def generate_product_key(self, plan: SubscriptionPlan) -> str:
        """
        Generate a valid product key with plan type.
        Format: SENT-{M/H/A}{3chars}-{4chars}-{4chars} (19 chars total)
        Last segment is checksum of first code+3chars+4chars.
        """
        segment1 = self._generate_segment(3)  # 3 chars instead of 4
        segment2 = self._generate_segment(4)
        
        # Create base key for checksum
        key_data = f"{plan.key_code}{segment1}{segment2}"
        checksum = self._calculate_checksum(key_data)
        
        # Use first 4 chars of checksum as segment3
        segment3 = checksum[:4]
        
        product_key = f"SENT-{plan.key_code}{segment1}-{segment2}-{segment3}"
        logger.info(f"[ACTIVATION] Generated {plan.display_name} key: {product_key}")
        return product_key
    
    def get_plan_from_key(self, product_key: str) -> Optional[SubscriptionPlan]:
        """Determine plan type from product key format."""
        try:
            if not product_key.startswith('SENT-'):
                return None
            
            # Extract plan code (character after SENT-)
            plan_code = product_key[5]  # Position 5 is where M/H/A would be
            
            for plan in SubscriptionPlan:
                if plan.key_code == plan_code:
                    return plan
            
            return None
        except (IndexError, ValueError):
            return None
    
    def validate_product_key(self, product_key: str) -> bool:
        """
        Validate a product key format and checksum.
        """
        try:
            # Check format: SENT-{M/H/A}XXX-XXXX-XXXX
            if not product_key.startswith('SENT-'):
                logger.warning(f"[ACTIVATION] Invalid key prefix: {product_key}")
                return False
            
            parts = product_key.split('-')
            if len(parts) != 4:
                logger.warning(f"[ACTIVATION] Invalid key format: {product_key}")
                return False
            
            prefix, seg1, seg2, seg3 = parts
            
            # Check plan code (first char of segment 1)
            plan_code = seg1[0]
            plan = self.get_plan_from_key(product_key)
            
            if plan is None:
                logger.warning(f"[ACTIVATION] Invalid plan code: {plan_code}")
                return False
            
            # Verify segment lengths: seg1 should be 4 chars (M/H/A + 3), seg2 and seg3 are 4 each
            if len(seg1) != 4 or len(seg2) != 4 or len(seg3) != 4:
                logger.warning(f"[ACTIVATION] Invalid segment length: {product_key}")
                return False
            
            # Verify checksum (calculate checksum of plan_code+3chars+4chars)
            key_data = seg1 + seg2  # This includes plan code
            expected_checksum = self._calculate_checksum(key_data)[:4]
            
            if seg3 != expected_checksum:
                logger.warning(f"[ACTIVATION] Checksum mismatch: {product_key}")
                return False
            
            logger.info(f"[ACTIVATION] Key validated successfully: {product_key} ({plan.display_name})")
            return True
            
        except Exception as e:
            logger.error(f"[ACTIVATION] Key validation error: {e}")
            return False
    
    def activate(self, product_key: str) -> bool:
        """
        Activate the system with a product key.
        """
        if not self.validate_product_key(product_key):
            logger.error(f"[ACTIVATION] Invalid product key: {product_key}")
            return False
        
        plan = self.get_plan_from_key(product_key)
        if plan is None:
            logger.error(f"[ACTIVATION] Could not determine plan from key: {product_key}")
            return False
        
        try:
            self.activation_file.parent.mkdir(parents=True, exist_ok=True)
            
            activation_date = datetime.now()
            expiration_date = activation_date + timedelta(days=plan.days)
            
            activation_data = {
                'product_key': product_key,
                'activation_date': activation_date.isoformat(),
                'expiration_date': expiration_date.isoformat(),
                'is_activated': True,
                'is_trial': False,
                'plan': plan.display_name
            }
            
            with open(self.activation_file, 'w') as f:
                json.dump(activation_data, f, indent=2)
            
            self.status = ActivationStatus(
                is_activated=True,
                product_key=product_key,
                activation_date=activation_date.isoformat(),
                trial_days_remaining=0,
                is_trial=False,
                expiration_date=expiration_date.isoformat(),
                plan=plan.display_name,
                plan_days_remaining=plan.days
            )
            
            logger.warning(f"[ACTIVATION] System activated with {plan.display_name} key: {product_key}")
            return True
            
        except Exception as e:
            logger.error(f"[ACTIVATION] Activation failed: {e}")
            return False
    
    def start_trial(self) -> bool:
        """
        Start a trial period (30 days from now).
        """
        try:
            self.activation_file.parent.mkdir(parents=True, exist_ok=True)
            
            expiration_date = (datetime.now() + timedelta(days=self.TRIAL_PERIOD_DAYS)).isoformat()
            
            activation_data = {
                'product_key': None,
                'activation_date': datetime.now().isoformat(),
                'expiration_date': expiration_date,
                'is_activated': False,
                'is_trial': True,
                'plan': None
            }
            
            with open(self.activation_file, 'w') as f:
                json.dump(activation_data, f, indent=2)
            
            self.status = ActivationStatus(
                is_activated=False,
                is_trial=True,
                trial_days_remaining=self.TRIAL_PERIOD_DAYS,
                activation_date=activation_data['activation_date'],
                expiration_date=expiration_date,
                plan=None
            )
            
            logger.info(f"[ACTIVATION] Trial period started - {self.TRIAL_PERIOD_DAYS} days")
            return True
            
        except Exception as e:
            logger.error(f"[ACTIVATION] Trial initialization failed: {e}")
            return False
    
    def _load_activation_status(self) -> ActivationStatus:
        """Load activation status from file."""
        try:
            if not self.activation_file.exists():
                logger.debug("[ACTIVATION] No activation file found - starting trial")
                self.start_trial()
                return self.status
            
            with open(self.activation_file, 'r') as f:
                data = json.load(f)
            
            # Check if activated
            if data.get('is_activated'):
                expiration_date = datetime.fromisoformat(data.get('expiration_date', ''))
                days_remaining = max(0, (expiration_date - datetime.now()).days)
                
                if days_remaining <= 0:
                    logger.warning("[ACTIVATION] License period expired!")
                    return ActivationStatus(
                        is_activated=False,
                        is_trial=False,
                        trial_days_remaining=0,
                        plan=None
                    )
                
                return ActivationStatus(
                    is_activated=True,
                    product_key=data.get('product_key'),
                    activation_date=data.get('activation_date'),
                    trial_days_remaining=0,
                    is_trial=False,
                    expiration_date=data.get('expiration_date'),
                    plan=data.get('plan'),
                    plan_days_remaining=days_remaining
                )
            
            # Check if trial
            if data.get('is_trial'):
                expiration_date = datetime.fromisoformat(data.get('expiration_date', ''))
                days_remaining = (expiration_date - datetime.now()).days
                
                if days_remaining <= 0:
                    logger.warning("[ACTIVATION] Trial period expired!")
                    return ActivationStatus(
                        is_activated=False,
                        is_trial=False,
                        trial_days_remaining=0
                    )
                
                return ActivationStatus(
                    is_activated=False,
                    is_trial=True,
                    trial_days_remaining=days_remaining,
                    expiration_date=data.get('expiration_date'),
                    plan=None
                )
            
            # No activation status - start trial
            self.start_trial()
            return self.status
            
        except Exception as e:
            logger.error(f"[ACTIVATION] Error loading activation status: {e}")
            self.start_trial()
            return self.status
    
    def get_status(self) -> ActivationStatus:
        """Get current activation status."""
        self.status = self._load_activation_status()
        return self.status
    
    def get_status_message(self) -> str:
        """Get human-readable status message."""
        status = self.get_status()
        
        if status.is_activated:
            plan_text = f" ({status.plan})" if status.plan else ""
            return f"[ACTIVATED] Licensed {plan_text} - {status.plan_days_remaining} days remaining"
        
        if status.is_trial:
            return f"[TRIAL] {status.trial_days_remaining} days remaining"
        
        return "[EXPIRED] License expired - Please activate with product key"
    
    def is_system_usable(self) -> bool:
        """Check if system is usable (activated or in trial)."""
        status = self.get_status()
        
        if status.is_activated:
            # Check if license hasn't expired
            if status.expiration_date:
                expiration = datetime.fromisoformat(status.expiration_date)
                if datetime.now() > expiration:
                    return False
            return True
        
        return status.is_trial
