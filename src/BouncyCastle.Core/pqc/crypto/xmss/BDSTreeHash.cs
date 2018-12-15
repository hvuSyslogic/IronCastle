using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.xmss
{


	[Serializable]
	public class BDSTreeHash
	{
		private const long serialVersionUID = 1L;

		private XMSSNode tailNode;
		private readonly int initialHeight;
		private int height;
		private int nextIndex;
		private bool initialized;
		private bool finished;

		public BDSTreeHash(int initialHeight) : base()
		{
			this.initialHeight = initialHeight;
			initialized = false;
			finished = false;
		}

		public virtual void initialize(int nextIndex)
		{
			tailNode = null;
			height = initialHeight;
			this.nextIndex = nextIndex;
			initialized = true;
			finished = false;
		}

		public virtual void update(Stack<XMSSNode> stack, WOTSPlus wotsPlus, byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
		{
			if (otsHashAddress == null)
			{
				throw new NullPointerException("otsHashAddress == null");
			}
			if (finished || !initialized)
			{
				throw new IllegalStateException("finished or not initialized");
			}
				/* prepare addresses */
			otsHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withOTSAddress(nextIndex).withChainAddress(otsHashAddress.getChainAddress()).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask()).build();
			LTreeAddress lTreeAddress = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withLTreeAddress(nextIndex).build();
			HashTreeAddress hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withTreeIndex(nextIndex).build();
				/* calculate leaf node */
			wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
			WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
			XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);

			while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight() && stack.peek().getHeight() != initialHeight)
			{
				hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
				node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress);
				node = new XMSSNode(node.getHeight() + 1, node.getValue());
				hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight() + 1).withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
			}

			if (tailNode == null)
			{
				tailNode = node;
			}
			else
			{
				if (tailNode.getHeight() == node.getHeight())
				{
					hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
					node = XMSSNodeUtil.randomizeHash(wotsPlus, tailNode, node, hashTreeAddress);
					node = new XMSSNode(tailNode.getHeight() + 1, node.getValue());
					tailNode = node;
					hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight() + 1).withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
				}
				else
				{
					stack.push(node);
				}
			}

			if (tailNode.getHeight() == initialHeight)
			{
				finished = true;
			}
			else
			{
				height = node.getHeight();
				nextIndex++;
			}
		}

		public virtual int getHeight()
		{
			if (!initialized || finished)
			{
				return int.MaxValue;
			}
			return height;
		}

		public virtual int getIndexLeaf()
		{
			return nextIndex;
		}

		public virtual void setNode(XMSSNode node)
		{
			tailNode = node;
			height = node.getHeight();
			if (height == initialHeight)
			{
				finished = true;
			}
		}

		public virtual bool isFinished()
		{
			return finished;
		}

		public virtual bool isInitialized()
		{
			return initialized;
		}

		public virtual XMSSNode getTailNode()
		{
			return tailNode.clone();
		}
	}


}