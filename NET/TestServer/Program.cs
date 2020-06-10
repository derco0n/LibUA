using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Timers;
using LibUA.Core;

namespace TestServer
{
    /// <summary>
    /// this is the main program
    /// </summary>
	class Program
	{
			
        /// <summary>
        /// Main Method
        /// </summary>
        /// <param name="args">None used</param>
		static void Main(string[] args)
		{
			//TestSerialization();
			TestServer();
		}

		private static void TestServer()
		{
			var sw = new Stopwatch();
			sw.Start();           
            try
            {
                var app = new DemoApplication();
			    var server = new LibUA.Server.Master(app, Types.TCPPortDefault, 10, 30, 100, new DemoLogger());
			    server.Start();

			    sw.Stop();
			    Console.WriteLine("Created and started server in {0} ms", sw.ElapsedMilliseconds.ToString("N3"));

			    var timer = new Timer(1000);
			    timer.Elapsed += (sender, e) =>
			    {
				    app.PlayRow();
			    };

			    timer.Start();
			    Console.ReadKey();
			    timer.Stop();

			    server.Stop();
            }
            catch (OperationCanceledException ex)
            {
                Console.WriteLine(ex.Message);
                System.Threading.Thread.Sleep(3500);
                
            }
            catch (Exception gex)
            {
                Console.WriteLine(gex.ToString());
                System.Threading.Thread.Sleep(3500);
                
            }
            
            return;
            
        }

		private static void TestSerialization()
		{
			var mbuf = new MemoryBuffer(1 << 25);
			const int numPasses = 1 << 20;
			double va = 2.31;
			int vb = 2321;

			var sw = new Stopwatch();
			sw.Start();
			for (int i = 0; i < numPasses; i++)
			{
				mbuf.VariantEncode(va);
				mbuf.VariantEncode(vb);
			}
			sw.Stop();
			//Console.WriteLine(((numPasses * 2) / (sw.Elapsed.TotalSeconds * 1024.0 * 1024.0)).ToString("N2"));
			Console.WriteLine("{0} KB/{1} KB in {2}",
				(mbuf.Position / 1024.0).ToString("N2"), (mbuf.Capacity / 1024.0).ToString("N2"),
				sw.Elapsed.ToString());
			mbuf.Rewind();

			sw.Restart();
			for (int i = 0; i < numPasses; i++)
			{
				object vra = null;
				mbuf.VariantDecode(out vra);
				mbuf.VariantDecode(out vra);
			}
			sw.Stop();
			Console.WriteLine("{0} KB/{1} KB in {2}",
				(mbuf.Position / 1024.0).ToString("N2"), (mbuf.Capacity / 1024.0).ToString("N2"),
				sw.Elapsed.ToString());

			var nodeDict = new Dictionary<NodeId, Node>();
			sw.Restart();
			for (int i = 0; i < (1 << 18); i++)
			{
				var node = new NodeVariable(new NodeId(2, (uint)(i + 100)), new QualifiedName(0, string.Format("V|{0}", i)), new LocalizedText(i.ToString()), new LocalizedText(i.ToString()), 0, 0, AccessLevel.CurrentRead, AccessLevel.CurrentRead, 0, false, NodeId.Zero);

				//bool put = nodeDict.TryAdd(node.Id, node);
				//Debug.Assert(put);
				nodeDict.Add(node.Id, node);
			}
			sw.Stop();
			Console.WriteLine("Created node objects in {0}, {1 }M/sec", sw.Elapsed.ToString(), ((nodeDict.Count / 1000000.0) / sw.Elapsed.TotalSeconds).ToString("N2"));
		}
	}
}
