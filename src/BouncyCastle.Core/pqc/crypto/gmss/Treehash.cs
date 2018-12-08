using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.gmss
{

	using Digest = org.bouncycastle.crypto.Digest;
	using GMSSRandom = org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
	using Integers = org.bouncycastle.util.Integers;
	using Hex = org.bouncycastle.util.encoders.Hex;


	/// <summary>
	/// This class implements a treehash instance for the Merkle tree traversal
	/// algorithm. The first node of the stack is stored in this instance itself,
	/// additional tail nodes are stored on a tailstack.
	/// </summary>
	public class Treehash
	{

		/// <summary>
		/// max height of current treehash instance.
		/// </summary>
		private int maxHeight;

		/// <summary>
		/// Vector element that stores the nodes on the stack
		/// </summary>
		private Vector tailStack;

		/// <summary>
		/// Vector element that stores the height of the nodes on the stack
		/// </summary>
		private Vector heightOfNodes;

		/// <summary>
		/// the first node is stored in the treehash instance itself, not on stack
		/// </summary>
		private byte[] firstNode;

		/// <summary>
		/// seedActive needed for the actual node
		/// </summary>
		private byte[] seedActive;

		/// <summary>
		/// the seed needed for the next re-initialization of the treehash instance
		/// </summary>
		private byte[] seedNext;

		/// <summary>
		/// number of nodes stored on the stack and belonging to this treehash
		/// instance
		/// </summary>
		private int tailLength;

		/// <summary>
		/// the height in the tree of the first node stored in treehash
		/// </summary>
		private int firstNodeHeight;

		/// <summary>
		/// true if treehash instance was already initialized, false otherwise
		/// </summary>
		private bool isInitialized;

		/// <summary>
		/// true if the first node's height equals the maxHeight of the treehash
		/// </summary>
		private bool isFinished;

		/// <summary>
		/// true if the nextSeed has been initialized with index 3*2^h needed for the
		/// seed scheduling
		/// </summary>
		private bool seedInitialized;

		/// <summary>
		/// denotes the Message Digest used by the tree to create nodes
		/// </summary>
		private Digest messDigestTree;

		/// <summary>
		/// This constructor regenerates a prior treehash object
		/// </summary>
		/// <param name="name">     an array of strings, containing the name of the used hash
		///                 function and PRNG and the name of the corresponding provider </param>
		/// <param name="statByte"> status bytes </param>
		/// <param name="statInt">  status ints </param>
		public Treehash(Digest name, byte[][] statByte, int[] statInt)
		{
			this.messDigestTree = name;

			// decode statInt
			this.maxHeight = statInt[0];
			this.tailLength = statInt[1];
			this.firstNodeHeight = statInt[2];

			if (statInt[3] == 1)
			{
				this.isFinished = true;
			}
			else
			{
				this.isFinished = false;
			}
			if (statInt[4] == 1)
			{
				this.isInitialized = true;
			}
			else
			{
				this.isInitialized = false;
			}
			if (statInt[5] == 1)
			{
				this.seedInitialized = true;
			}
			else
			{
				this.seedInitialized = false;
			}

			this.heightOfNodes = new Vector();
			for (int i = 0; i < tailLength; i++)
			{
				this.heightOfNodes.addElement(Integers.valueOf(statInt[6 + i]));
			}

			// decode statByte
			this.firstNode = statByte[0];
			this.seedActive = statByte[1];
			this.seedNext = statByte[2];

			this.tailStack = new Vector();
			for (int i = 0; i < tailLength; i++)
			{
				this.tailStack.addElement(statByte[3 + i]);
			}
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="tailStack"> a vector element where the stack nodes are stored </param>
		/// <param name="maxHeight"> maximal height of the treehash instance </param>
		/// <param name="digest">    an array of strings, containing the name of the used hash
		///                  function and PRNG and the name of the corresponding provider </param>
		public Treehash(Vector tailStack, int maxHeight, Digest digest)
		{
			this.tailStack = tailStack;
			this.maxHeight = maxHeight;
			this.firstNode = null;
			this.isInitialized = false;
			this.isFinished = false;
			this.seedInitialized = false;
			this.messDigestTree = digest;

			this.seedNext = new byte[messDigestTree.getDigestSize()];
			this.seedActive = new byte[messDigestTree.getDigestSize()];
		}

		/// <summary>
		/// Method to initialize the seeds needed for the precomputation of right
		/// nodes. Should be initialized with index 3*2^i for treehash_i
		/// </summary>
		/// <param name="seedIn"> </param>
		public virtual void initializeSeed(byte[] seedIn)
		{
			JavaSystem.arraycopy(seedIn, 0, this.seedNext, 0, this.messDigestTree.getDigestSize());
			this.seedInitialized = true;
		}

		/// <summary>
		/// initializes the treehash instance. The seeds must already have been
		/// initialized to work correctly.
		/// </summary>
		public virtual void initialize()
		{
			if (!this.seedInitialized)
			{
				JavaSystem.err.println("Seed " + this.maxHeight + " not initialized");
				return;
			}

			this.heightOfNodes = new Vector();
			this.tailLength = 0;
			this.firstNode = null;
			this.firstNodeHeight = -1;
			this.isInitialized = true;
			JavaSystem.arraycopy(this.seedNext, 0, this.seedActive, 0, messDigestTree.getDigestSize());
		}

		/// <summary>
		/// Calculates one update of the treehash instance, i.e. creates a new leaf
		/// and hashes if possible
		/// </summary>
		/// <param name="gmssRandom"> an instance of the PRNG </param>
		/// <param name="leaf">       The byte value of the leaf needed for the update </param>
		public virtual void update(GMSSRandom gmssRandom, byte[] leaf)
		{

			if (this.isFinished)
			{
				JavaSystem.err.println("No more update possible for treehash instance!");
				return;
			}
			if (!this.isInitialized)
			{
				JavaSystem.err.println("Treehash instance not initialized before update");
				return;
			}

			byte[] help = new byte[this.messDigestTree.getDigestSize()];
			int helpHeight = -1;

			gmssRandom.nextSeed(this.seedActive);

			// if treehash gets first update
			if (this.firstNode == null)
			{
				this.firstNode = leaf;
				this.firstNodeHeight = 0;
			}
			else
			{
				// store the new node in help array, do not push it on the stack
				help = leaf;
				helpHeight = 0;

				// hash the nodes on the stack if possible
				while (this.tailLength > 0 && helpHeight == ((int?)heightOfNodes.lastElement()).Value)
				{
					// put top element of the stack and help node in array
					// 'tobehashed'
					// and hash them together, put result again in help array
					byte[] toBeHashed = new byte[this.messDigestTree.getDigestSize() << 1];

					// pop element from stack
					JavaSystem.arraycopy(this.tailStack.lastElement(), 0, toBeHashed, 0, this.messDigestTree.getDigestSize());
					this.tailStack.removeElementAt(this.tailStack.size() - 1);
					this.heightOfNodes.removeElementAt(this.heightOfNodes.size() - 1);

					JavaSystem.arraycopy(help, 0, toBeHashed, this.messDigestTree.getDigestSize(), this.messDigestTree.getDigestSize());
					messDigestTree.update(toBeHashed, 0, toBeHashed.Length);
					help = new byte[messDigestTree.getDigestSize()];
					messDigestTree.doFinal(help, 0);

					// increase help height, stack was reduced by one element
					helpHeight++;
					this.tailLength--;
				}

				// push the new node on the stack
				this.tailStack.addElement(help);
				this.heightOfNodes.addElement(Integers.valueOf(helpHeight));
				this.tailLength++;

				// finally check whether the top node on stack and the first node
				// in treehash have same height. If so hash them together
				// and store them in treehash
				if (((int?)heightOfNodes.lastElement()).Value == this.firstNodeHeight)
				{
					byte[] toBeHashed = new byte[this.messDigestTree.getDigestSize() << 1];
					JavaSystem.arraycopy(this.firstNode, 0, toBeHashed, 0, this.messDigestTree.getDigestSize());

					// pop element from tailStack and copy it into help2 array
					JavaSystem.arraycopy(this.tailStack.lastElement(), 0, toBeHashed, this.messDigestTree.getDigestSize(), this.messDigestTree.getDigestSize());
					this.tailStack.removeElementAt(this.tailStack.size() - 1);
					this.heightOfNodes.removeElementAt(this.heightOfNodes.size() - 1);

					// store new element in firstNode, stack is then empty
					messDigestTree.update(toBeHashed, 0, toBeHashed.Length);
					this.firstNode = new byte[messDigestTree.getDigestSize()];
					messDigestTree.doFinal(this.firstNode, 0);
					this.firstNodeHeight++;

					// empty the stack
					this.tailLength = 0;
				}
			}

			// check if treehash instance is completed
			if (this.firstNodeHeight == this.maxHeight)
			{
				this.isFinished = true;
			}
		}

		/// <summary>
		/// Destroys a treehash instance after the top node was taken for
		/// authentication path.
		/// </summary>
		public virtual void destroy()
		{
			this.isInitialized = false;
			this.isFinished = false;
			this.firstNode = null;
			this.tailLength = 0;
			this.firstNodeHeight = -1;
		}

		/// <summary>
		/// Returns the height of the lowest node stored either in treehash or on the
		/// stack. It must not be set to infinity (as mentioned in the paper) because
		/// this cases are considered in the computeAuthPaths method of
		/// JDKGMSSPrivateKey
		/// </summary>
		/// <returns> Height of the lowest node </returns>
		public virtual int getLowestNodeHeight()
		{
			if (this.firstNode == null)
			{
				return this.maxHeight;
			}
			else if (this.tailLength == 0)
			{
				return this.firstNodeHeight;
			}
			else
			{
				return Math.Min(this.firstNodeHeight, ((int?)heightOfNodes.lastElement()).Value);
			}
		}

		/// <summary>
		/// Returns the top node height
		/// </summary>
		/// <returns> Height of the first node, the top node </returns>
		public virtual int getFirstNodeHeight()
		{
			if (firstNode == null)
			{
				return maxHeight;
			}
			return firstNodeHeight;
		}

		/// <summary>
		/// Method to check whether the instance has been initialized or not
		/// </summary>
		/// <returns> true if treehash was already initialized </returns>
		public virtual bool wasInitialized()
		{
			return this.isInitialized;
		}

		/// <summary>
		/// Method to check whether the instance has been finished or not
		/// </summary>
		/// <returns> true if treehash has reached its maximum height </returns>
		public virtual bool wasFinished()
		{
			return this.isFinished;
		}

		/// <summary>
		/// returns the first node stored in treehash instance itself
		/// </summary>
		/// <returns> the first node stored in treehash instance itself </returns>
		public virtual byte[] getFirstNode()
		{
			return this.firstNode;
		}

		/// <summary>
		/// returns the active seed
		/// </summary>
		/// <returns> the active seed </returns>
		public virtual byte[] getSeedActive()
		{
			return this.seedActive;
		}

		/// <summary>
		/// This method sets the first node stored in the treehash instance itself
		/// </summary>
		/// <param name="hash"> </param>
		public virtual void setFirstNode(byte[] hash)
		{
			if (!this.isInitialized)
			{
				this.initialize();
			}
			this.firstNode = hash;
			this.firstNodeHeight = this.maxHeight;
			this.isFinished = true;
		}

		/// <summary>
		/// updates the nextSeed of this treehash instance one step needed for the
		/// schedulng of the seeds
		/// </summary>
		/// <param name="gmssRandom"> the prng used for the seeds </param>
		public virtual void updateNextSeed(GMSSRandom gmssRandom)
		{
			gmssRandom.nextSeed(seedNext);
		}

		/// <summary>
		/// Returns the tailstack
		/// </summary>
		/// <returns> the tailstack </returns>
		public virtual Vector getTailStack()
		{
			return this.tailStack;
		}

		/// <summary>
		/// Returns the status byte array used by the GMSSPrivateKeyASN.1 class
		/// </summary>
		/// <returns> The status bytes </returns>
		public virtual byte[][] getStatByte()
		{

//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] statByte = new byte[3 + tailLength][this.messDigestTree.getDigestSize()];
			byte[][] statByte = RectangularArrays.ReturnRectangularSbyteArray(3 + tailLength, this.messDigestTree.getDigestSize());
			statByte[0] = firstNode;
			statByte[1] = seedActive;
			statByte[2] = seedNext;
			for (int i = 0; i < tailLength; i++)
			{
				statByte[3 + i] = (byte[])tailStack.elementAt(i);
			}
			return statByte;
		}

		/// <summary>
		/// Returns the status int array used by the GMSSPrivateKeyASN.1 class
		/// </summary>
		/// <returns> The status ints </returns>
		public virtual int[] getStatInt()
		{

			int[] statInt = new int[6 + tailLength];
			statInt[0] = maxHeight;
			statInt[1] = tailLength;
			statInt[2] = firstNodeHeight;
			if (this.isFinished)
			{
				statInt[3] = 1;
			}
			else
			{
				statInt[3] = 0;
			}
			if (this.isInitialized)
			{
				statInt[4] = 1;
			}
			else
			{
				statInt[4] = 0;
			}
			if (this.seedInitialized)
			{
				statInt[5] = 1;
			}
			else
			{
				statInt[5] = 0;
			}
			for (int i = 0; i < tailLength; i++)
			{
				statInt[6 + i] = ((int?)heightOfNodes.elementAt(i)).Value;
			}
			return statInt;
		}

		/// <summary>
		/// returns a String representation of the treehash instance
		/// </summary>
		public override string ToString()
		{
			string @out = "Treehash    : ";
			for (int i = 0; i < 6 + tailLength; i++)
			{
				@out = @out + this.getStatInt()[i] + " ";
			}
			for (int i = 0; i < 3 + tailLength; i++)
			{
				if (this.getStatByte()[i] != null)
				{
					@out = @out + StringHelper.NewString(Hex.encode((this.getStatByte()[i]))) + " ";
				}
				else
				{
					@out = @out + "null ";
				}
			}
			@out = @out + "  " + this.messDigestTree.getDigestSize();
			return @out;
		}

	}
}