using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.xmss
{
	public class XMSSNodeUtil
	{
		/// <summary>
		/// Compresses a WOTS+ public key to a single n-byte string.
		/// </summary>
		/// <param name="publicKey"> WOTS+ public key to compress. </param>
		/// <param name="address">   Address. </param>
		/// <returns> Compressed n-byte string of public key. </returns>
		internal static XMSSNode lTree(WOTSPlus wotsPlus, WOTSPlusPublicKeyParameters publicKey, LTreeAddress address)
		{
			if (publicKey == null)
			{
				throw new NullPointerException("publicKey == null");
			}
			if (address == null)
			{
				throw new NullPointerException("address == null");
			}
			int len = wotsPlus.getParams().getLen();
				/* duplicate public key to XMSSNode Array */
			byte[][] publicKeyBytes = publicKey.toByteArray();
			XMSSNode[] publicKeyNodes = new XMSSNode[publicKeyBytes.Length];
			for (int i = 0; i < publicKeyBytes.Length; i++)
			{
				publicKeyNodes[i] = new XMSSNode(0, publicKeyBytes[i]);
			}
			address = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress()).withTreeHeight(0).withTreeIndex(address.getTreeIndex()).withKeyAndMask(address.getKeyAndMask()).build();
			while (len > 1)
			{
				for (int i = 0; i < (int)Math.floor(len / 2); i++)
				{
					address = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress()).withTreeHeight(address.getTreeHeight()).withTreeIndex(i).withKeyAndMask(address.getKeyAndMask()).build();
					publicKeyNodes[i] = randomizeHash(wotsPlus, publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1], address);
				}
				if (len % 2 == 1)
				{
					publicKeyNodes[(int)Math.floor(len / 2)] = publicKeyNodes[len - 1];
				}
				len = (int)Math.ceil((double)len / 2);
				address = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress()).withTreeHeight(address.getTreeHeight() + 1).withTreeIndex(address.getTreeIndex()).withKeyAndMask(address.getKeyAndMask()).build();
			}
			return publicKeyNodes[0];
		}

		/// <summary>
		/// Randomization of nodes in binary tree.
		/// </summary>
		/// <param name="left">    Left node. </param>
		/// <param name="right">   Right node. </param>
		/// <param name="address"> Address. </param>
		/// <returns> Randomized hash of parent of left / right node. </returns>
		internal static XMSSNode randomizeHash(WOTSPlus wotsPlus, XMSSNode left, XMSSNode right, XMSSAddress address)
		{
			if (left == null)
			{
				throw new NullPointerException("left == null");
			}
			if (right == null)
			{
				throw new NullPointerException("right == null");
			}
			if (left.getHeight() != right.getHeight())
			{
				throw new IllegalStateException("height of both nodes must be equal");
			}
			if (address == null)
			{
				throw new NullPointerException("address == null");
			}
			byte[] publicSeed = wotsPlus.getPublicSeed();

			if (address is LTreeAddress)
			{
				LTreeAddress tmpAddress = (LTreeAddress)address;
				address = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(tmpAddress.getLayerAddress()).withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(0).build();
			}
			else if (address is HashTreeAddress)
			{
				HashTreeAddress tmpAddress = (HashTreeAddress)address;
				address = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(tmpAddress.getLayerAddress()).withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(0).build();
			}

			byte[] key = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());

			if (address is LTreeAddress)
			{
				LTreeAddress tmpAddress = (LTreeAddress)address;
				address = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(tmpAddress.getLayerAddress()).withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(1).build();
			}
			else if (address is HashTreeAddress)
			{
				HashTreeAddress tmpAddress = (HashTreeAddress)address;
				address = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(tmpAddress.getLayerAddress()).withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(1).build();
			}

			byte[] bitmask0 = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());

			if (address is LTreeAddress)
			{
				LTreeAddress tmpAddress = (LTreeAddress)address;
				address = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(tmpAddress.getLayerAddress()).withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(2).build();
			}
			else if (address is HashTreeAddress)
			{
				HashTreeAddress tmpAddress = (HashTreeAddress)address;
				address = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(tmpAddress.getLayerAddress()).withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(2).build();
			}

			byte[] bitmask1 = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());
			int n = wotsPlus.getParams().getDigestSize();
			byte[] tmpMask = new byte[2 * n];
			for (int i = 0; i < n; i++)
			{
				tmpMask[i] = (byte)(left.getValue()[i] ^ bitmask0[i]);
			}
			for (int i = 0; i < n; i++)
			{
				tmpMask[i + n] = (byte)(right.getValue()[i] ^ bitmask1[i]);
			}
			byte[] @out = wotsPlus.getKhf().H(key, tmpMask);
			return new XMSSNode(left.getHeight(), @out);
		}
	}

}