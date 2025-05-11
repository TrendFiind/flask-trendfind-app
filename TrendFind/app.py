import os
import asyncio
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed
from solders.pubkey import Pubkey
from solders.rpc.responses import GetTokenAccountsByOwnerResponse
import json
import aiohttp
from datetime import datetime
import logging
from flask import Flask, render_template, request, jsonify

# Initialize Flask app
app = Flask(__name__)

# Configuration
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
JUPITER_API_URL = "https://price.jup.ag/v4/price"
RAYDIUM_API_URL = "https://api.raydium.io/v2/main/price"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SolanaBot")

class SolanaBot:
    def __init__(self):
        self.client = None
        self.session = None
        self.token_cache = {}
        self.active_tokens = []
        self.last_updated = None
        
    async def initialize(self):
        """Initialize connections"""
        self.client = AsyncClient(SOLANA_RPC_URL)
        self.session = aiohttp.ClientSession()
        
    async def close(self):
        """Clean up connections"""
        if self.client:
            await self.client.close()
        if self.session:
            await self.session.close()
            
    async def discover_active_tokens(self):
        """Discover active memecoins using Jupiter API"""
        try:
            params = {
                "ids": "all",
                "vsToken": "So11111111111111111111111111111111111111112"  # SOL
            }
            
            async with self.session.get(JUPITER_API_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    tokens = data.get('data', [])
                    
                    # Filter for memecoins (simple heuristic - low price and high volume)
                    memecoins = [
                        t for t in tokens 
                        if float(t['price']) < 0.1 and float(t['volume24h']) > 1000
                    ]
                    
                    self.active_tokens = memecoins[:50]  # Limit to top 50
                    self.last_updated = datetime.now().isoformat()
                    return memecoins[:50]
                
        except Exception as e:
            logger.error(f"Error discovering tokens: {str(e)}")
            return []
            
    async def get_token_metadata(self, mint_address):
        """Get token metadata from Solana chain"""
        try:
            if mint_address in self.token_cache:
                return self.token_cache[mint_address]
                
            # Get token info
            pubkey = Pubkey.from_string(mint_address)
            account_info = await self.client.get_account_info(pubkey)
            
            if account_info.value:
                # Basic metadata extraction
                metadata = {
                    'mint': mint_address,
                    'decimals': 9,  # Default, would need proper parsing
                    'supply': None,
                    'owner': str(account_info.value.owner)
                }
                
                self.token_cache[mint_address] = metadata
                return metadata
                
        except Exception as e:
            logger.error(f"Error getting metadata for {mint_address}: {str(e)}")
            return None
            
    async def get_liquidity_data(self, mint_address):
        """Get liquidity data from Raydium API"""
        try:
            async with self.session.get(f"{RAYDIUM_API_URL}?ids={mint_address}") as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {}).get(mint_address, {})
        except Exception as e:
            logger.error(f"Error getting liquidity for {mint_address}: {str(e)}")
            return {}
            
    async def get_token_price(self, mint_address):
        """Get token price from Jupiter API"""
        try:
            params = {
                "ids": mint_address,
                "vsToken": "So11111111111111111111111111111111111111112"  # SOL
            }
            
            async with self.session.get(JUPITER_API_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {}).get(mint_address, {})
        except Exception as e:
            logger.error(f"Error getting price for {mint_address}: {str(e)}")
            return {}

# Global bot instance
bot = SolanaBot()

@app.route('/tbot')
async def tbot():
    """Main trading bot page"""
    if not bot.client:
        await bot.initialize()
        
    # Get initial data
    tokens = await bot.discover_active_tokens()
    
    # Get detailed data for first 5 tokens (for performance)
    detailed_tokens = []
    for token in tokens[:5]:
        mint_address = token['id']
        metadata = await bot.get_token_metadata(mint_address)
        liquidity = await bot.get_liquidity_data(mint_address)
        price_data = await bot.get_token_price(mint_address)
        
        detailed_tokens.append({
            **token,
            'metadata': metadata,
            'liquidity': liquidity,
            'price_data': price_data,
            'last_updated': datetime.now().isoformat()
        })
    
    return render_template('tbot.html', 
                         tokens=detailed_tokens,
                         last_updated=bot.last_updated)

@app.route('/tbot/update')
async def update_data():
    """Endpoint for live updates"""
    try:
        tokens = await bot.discover_active_tokens()
        
        updated_tokens = []
        for token in tokens[:5]:  # Limit to 5 for performance
            mint_address = token['id']
            liquidity = await bot.get_liquidity_data(mint_address)
            price_data = await bot.get_token_price(mint_address)
            
            updated_tokens.append({
                **token,
                'liquidity': liquidity,
                'price_data': price_data,
                'last_updated': datetime.now().isoformat()
            })
            
        return jsonify({
            'success': True,
            'tokens': updated_tokens,
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Update error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.before_first_request
async def startup():
    await bot.initialize()

@app.teardown_appcontext
async def shutdown(exception=None):
    await bot.close()
