using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.gmss
{

	using Digest = org.bouncycastle.crypto.Digest;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;
	using Hex = org.bouncycastle.util.encoders.Hex;


	/// <summary>
	/// This class computes a whole Merkle tree and saves the needed values for
	/// AuthPath computation. It is used for precomputation of the root of a
	/// following tree. After initialization, 2^H updates are required to complete
	/// the root. Every update requires one leaf value as parameter. While computing
	/// the root all initial values for the authentication path algorithm (treehash,
	/// auth, retain) are stored for later use.
	/// </summary>
	public class GMSSRootCalc
	{

		/// <summary>
		/// max height of the tree
		/// </summary>
		private int heightOfTree;

		/// <summary>
		/// length of the messageDigest
		/// </summary>
		private int mdLength;

		/// <summary>
		/// the treehash instances of the tree
		/// </summary>
		private Treehash[] treehash;

		/// <summary>
		/// stores the retain nodes for authPath computation
		/// </summary>
		private Vector[] retain;

		/// <summary>
		/// finally stores the root of the tree when finished
		/// </summary>
		private byte[] root;

		/// <summary>
		/// stores the authentication path y_1(i), i = 0..H-1
		/// </summary>
		private byte[][] AuthPath;

		/// <summary>
		/// the value K for the authentication path computation
		/// </summary>
		private int K;

		/// <summary>
		/// Vector element that stores the nodes on the stack
		/// </summary>
		private Vector tailStack;

		/// <summary>
		/// stores the height of all nodes laying on the tailStack
		/// </summary>
		private Vector heightOfNodes;
		/// <summary>
		/// The hash function used for the construction of the authentication trees
		/// </summary>
		private Digest messDigestTree;

		/// <summary>
		/// An array of strings containing the name of the hash function used to
		/// construct the authentication trees and used by the OTS.
		/// </summary>
		private GMSSDigestProvider digestProvider;

		/// <summary>
		/// stores the index of the current node on each height of the tree
		/// </summary>
		private int[] index;

		/// <summary>
		/// true if instance was already initialized, false otherwise
		/// </summary>
		private bool isInitialized;

		/// <summary>
		/// true it instance was finished
		/// </summary>
		private bool isFinished;

		/// <summary>
		/// Integer that stores the index of the next seed that has to be omitted to
		/// the treehashs
		/// </summary>
		private int indexForNextSeed;

		/// <summary>
		/// temporary integer that stores the height of the next treehash instance
		/// that gets initialized with a seed
		/// </summary>
		private int heightOfNextSeed;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="heightOfTree"> maximal height of the tree </param>
		/// <param name="digestProvider">       an array of strings, containing the name of the used hash
		///                     function and PRNG and the name of the corresponding
		///                     provider </param>
		public GMSSRootCalc(int heightOfTree, int K, GMSSDigestProvider digestProvider)
		{
			this.heightOfTree = heightOfTree;
			this.digestProvider = digestProvider;
			this.messDigestTree = digestProvider.get();
			this.mdLength = messDigestTree.getDigestSize();
			this.K = K;
			this.index = new int[heightOfTree];
			this.AuthPath = RectangularArrays.ReturnRectangularSbyteArray(heightOfTree, mdLength);
			this.root = new byte[mdLength];
			// this.treehash = new Treehash[this.heightOfTree - this.K];
			this.retain = new Vector[this.K - 1];
			for (int i = 0; i < K - 1; i++)
			{
				this.retain[i] = new Vector();
			}

		}

		/// <summary>
		/// Initializes the calculation of a new root
		/// </summary>
		/// <param name="sharedStack"> the stack shared by all treehash instances of this tree </param>
		public virtual void initialize(Vector sharedStack)
		{
			this.treehash = new Treehash[this.heightOfTree - this.K];
			for (int i = 0; i < this.heightOfTree - this.K; i++)
			{
				this.treehash[i] = new Treehash(sharedStack, i, this.digestProvider.get());
			}

			this.index = new int[heightOfTree];
			this.AuthPath = RectangularArrays.ReturnRectangularSbyteArray(heightOfTree, mdLength);
			this.root = new byte[mdLength];

			this.tailStack = new Vector();
			this.heightOfNodes = new Vector();
			this.isInitialized = true;
			this.isFinished = false;

			for (int i = 0; i < heightOfTree; i++)
			{
				this.index[i] = -1;
			}

			this.retain = new Vector[this.K - 1];
			for (int i = 0; i < K - 1; i++)
			{
				this.retain[i] = new Vector();
			}

			this.indexForNextSeed = 3;
			this.heightOfNextSeed = 0;
		}

		/// <summary>
		/// updates the root with one leaf and stores needed values in retain,
		/// treehash or authpath. Additionally counts the seeds used. This method is
		/// used when performing the updates for TREE++.
		/// </summary>
		/// <param name="seed"> the initial seed for treehash: seedNext </param>
		/// <param name="leaf"> the height of the treehash </param>
		public virtual void update(byte[] seed, byte[] leaf)
		{
			if (this.heightOfNextSeed < (this.heightOfTree - this.K) && this.indexForNextSeed - 2 == index[0])
			{
				this.initializeTreehashSeed(seed, this.heightOfNextSeed);
				this.heightOfNextSeed++;
				this.indexForNextSeed *= 2;
			}
			// now call the simple update
			this.update(leaf);
		}

		/// <summary>
		/// Updates the root with one leaf and stores the needed values in retain,
		/// treehash or authpath
		/// </summary>
		public virtual void update(byte[] leaf)
		{

			if (isFinished)
			{
				JavaSystem.@out.print("Too much updates for Tree!!");
				return;
			}
			if (!isInitialized)
			{
				JavaSystem.err.println("GMSSRootCalc not initialized!");
				return;
			}

			// a new leaf was omitted, so raise index on lowest layer
			index[0]++;

			// store the nodes on the lowest layer in treehash or authpath
			if (index[0] == 1)
			{
				JavaSystem.arraycopy(leaf, 0, AuthPath[0], 0, mdLength);
			}
			else if (index[0] == 3)
			{
				// store in treehash only if K < H
				if (heightOfTree > K)
				{
					treehash[0].setFirstNode(leaf);
				}
			}

			if ((index[0] - 3) % 2 == 0 && index[0] >= 3)
			{
				// store in retain if K = H
				if (heightOfTree == K)
				{
				// TODO: check it
					retain[0].insertElementAt(leaf, 0);
				}
			}

			// if first update to this tree is made
			if (index[0] == 0)
			{
				tailStack.addElement(leaf);
				heightOfNodes.addElement(Integers.valueOf(0));
			}
			else
			{

				byte[] help = new byte[mdLength];
				byte[] toBeHashed = new byte[mdLength << 1];

				// store the new leaf in help
				JavaSystem.arraycopy(leaf, 0, help, 0, mdLength);
				int helpHeight = 0;
				// while top to nodes have same height
				while (tailStack.size() > 0 && helpHeight == ((int?)heightOfNodes.lastElement()).Value)
				{

					// help <-- hash(stack top element || help)
					JavaSystem.arraycopy((byte[])tailStack.lastElement(), 0, toBeHashed, 0, mdLength);
					tailStack.removeElementAt(tailStack.size() - 1);
					heightOfNodes.removeElementAt(heightOfNodes.size() - 1);
					JavaSystem.arraycopy(help, 0, toBeHashed, mdLength, mdLength);

					messDigestTree.update(toBeHashed, 0, toBeHashed.Length);
					help = new byte[messDigestTree.getDigestSize()];
					messDigestTree.doFinal(help, 0);

					// the new help node is one step higher
					helpHeight++;
					if (helpHeight < heightOfTree)
					{
						index[helpHeight]++;

						// add index 1 element to initial authpath
						if (index[helpHeight] == 1)
						{
							JavaSystem.arraycopy(help, 0, AuthPath[helpHeight], 0, mdLength);
						}

						if (helpHeight >= heightOfTree - K)
						{
							if (helpHeight == 0)
							{
								JavaSystem.@out.println("M���P");
							}
							// add help element to retain stack if it is a right
							// node
							// and not stored in treehash
							if ((index[helpHeight] - 3) % 2 == 0 && index[helpHeight] >= 3)
							{
							// TODO: check it
								retain[helpHeight - (heightOfTree - K)].insertElementAt(help, 0);
							}
						}
						else
						{
							// if element is third in his line add it to treehash
							if (index[helpHeight] == 3)
							{
								treehash[helpHeight].setFirstNode(help);
							}
						}
					}
				}
				// push help element to the stack
				tailStack.addElement(help);
				heightOfNodes.addElement(Integers.valueOf(helpHeight));

				// is the root calculation finished?
				if (helpHeight == heightOfTree)
				{
					isFinished = true;
					isInitialized = false;
					root = (byte[])tailStack.lastElement();
				}
			}

		}

		/// <summary>
		/// initializes the seeds for the treehashs of the tree precomputed by this
		/// class
		/// </summary>
		/// <param name="seed">  the initial seed for treehash: seedNext </param>
		/// <param name="index"> the height of the treehash </param>
		public virtual void initializeTreehashSeed(byte[] seed, int index)
		{
			treehash[index].initializeSeed(seed);
		}

		/// <summary>
		/// Method to check whether the instance has been initialized or not
		/// </summary>
		/// <returns> true if treehash was already initialized </returns>
		public virtual bool wasInitialized()
		{
			return isInitialized;
		}

		/// <summary>
		/// Method to check whether the instance has been finished or not
		/// </summary>
		/// <returns> true if tree has reached its maximum height </returns>
		public virtual bool wasFinished()
		{
			return isFinished;
		}

		/// <summary>
		/// returns the authentication path of the first leaf of the tree
		/// </summary>
		/// <returns> the authentication path of the first leaf of the tree </returns>
		public virtual byte[][] getAuthPath()
		{
			return GMSSUtils.clone(AuthPath);
		}

		/// <summary>
		/// returns the initial treehash instances, storing value y_3(i)
		/// </summary>
		/// <returns> the initial treehash instances, storing value y_3(i) </returns>
		public virtual Treehash[] getTreehash()
		{
			return GMSSUtils.clone(treehash);
		}

		/// <summary>
		/// returns the retain stacks storing all right nodes near to the root
		/// </summary>
		/// <returns> the retain stacks storing all right nodes near to the root </returns>
		public virtual Vector[] getRetain()
		{
			return GMSSUtils.clone(retain);
		}

		/// <summary>
		/// returns the finished root value
		/// </summary>
		/// <returns> the finished root value </returns>
		public virtual byte[] getRoot()
		{
			return Arrays.clone(root);
		}

		/// <summary>
		/// returns the shared stack
		/// </summary>
		/// <returns> the shared stack </returns>
		public virtual Vector getStack()
		{
			Vector copy = new Vector();
			for (Enumeration en = tailStack.elements(); en.hasMoreElements();)
			{
				copy.addElement(en.nextElement());
			}
			return copy;
		}

		/// <summary>
		/// Returns the status byte array used by the GMSSPrivateKeyASN.1 class
		/// </summary>
		/// <returns> The status bytes </returns>
		public virtual byte[][] getStatByte()
		{

			int tailLength;
			if (tailStack == null)
			{
				tailLength = 0;
			}
			else
			{
				tailLength = tailStack.size();
			}
			byte[][] statByte = RectangularArrays.ReturnRectangularSbyteArray(1 + heightOfTree + tailLength, 64); //FIXME: messDigestTree.getByteLength()
			statByte[0] = root;

			for (int i = 0; i < heightOfTree; i++)
			{
				statByte[1 + i] = AuthPath[i];
			}
			for (int i = 0; i < tailLength; i++)
			{
				statByte[1 + heightOfTree + i] = (byte[])tailStack.elementAt(i);
			}

			return statByte;
		}

		/// <summary>
		/// Returns the status int array used by the GMSSPrivateKeyASN.1 class
		/// </summary>
		/// <returns> The status ints </returns>
		public virtual int[] getStatInt()
		{

			int tailLength;
			if (tailStack == null)
			{
				tailLength = 0;
			}
			else
			{
				tailLength = tailStack.size();
			}
			int[] statInt = new int[8 + heightOfTree + tailLength];
			statInt[0] = heightOfTree;
			statInt[1] = mdLength;
			statInt[2] = K;
			statInt[3] = indexForNextSeed;
			statInt[4] = heightOfNextSeed;
			if (isFinished)
			{
				statInt[5] = 1;
			}
			else
			{
				statInt[5] = 0;
			}
			if (isInitialized)
			{
				statInt[6] = 1;
			}
			else
			{
				statInt[6] = 0;
			}
			statInt[7] = tailLength;

			for (int i = 0; i < heightOfTree; i++)
			{
				statInt[8 + i] = index[i];
			}
			for (int i = 0; i < tailLength; i++)
			{
				statInt[8 + heightOfTree + i] = ((int?)heightOfNodes.elementAt(i)).Value;
			}

			return statInt;
		}

		/// <returns> a human readable version of the structure </returns>
		public override string ToString()
		{
			string @out = "";
			int tailLength;
			if (tailStack == null)
			{
				tailLength = 0;
			}
			else
			{
				tailLength = tailStack.size();
			}

			for (int i = 0; i < 8 + heightOfTree + tailLength; i++)
			{
				@out = @out + getStatInt()[i] + " ";
			}
			for (int i = 0; i < 1 + heightOfTree + tailLength; i++)
			{
				@out = @out + StringHelper.NewString(Hex.encode(getStatByte()[i])) + " ";
			}
			@out = @out + "  " + digestProvider.get().getDigestSize();
			return @out;
		}
	}

}