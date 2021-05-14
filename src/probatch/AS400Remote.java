package probatch;

import com.ibm.as400.access.AS400;
import com.ibm.as400.access.AS400FileRecordDescription;
import com.ibm.as400.access.AS400JPing;
import com.ibm.as400.access.AS400Message;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.CommandCall;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.IFSFile;
import com.ibm.as400.access.IFSFileReader;
import com.ibm.as400.access.Job;
import com.ibm.as400.access.JobList;
import com.ibm.as400.access.JobLog;
import com.ibm.as400.access.ObjectDoesNotExistException;
import com.ibm.as400.access.QueuedMessage;
import com.ibm.as400.access.Record;
import com.ibm.as400.access.RecordFormat;
import com.ibm.as400.access.SequentialFile;
import com.ibm.as400.access.SystemValue;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AS400Remote {

	private static class RunCommand implements Runnable {
		CommandCall cmd;
		private boolean result;

		public RunCommand(CommandCall c) {
			this.cmd = c;
		}

		public boolean sucessfulExecution() {
			return this.result;
		}

		public void run() {
			try {
				this.result = this.cmd.run();
			} catch (Exception e) {

				System.out.println("Command " + this.cmd.getCommand() + " issued an exception!");
				e.printStackTrace();
			}
		}
	}

	private static class ShutdownThread extends Thread {
		private Job job;

		ShutdownThread(Job job, Job job_mon) {
			this.job = job;
			this.job_mon = job_mon;
		}

		private Job job_mon;

		public void run() {
			try {
				System.out.println("Voy a matar el job");
				this.job_mon.end(-1);
				this.job.end(-1);
				System.out.println("Mate el job");
			} catch (Exception exception) {
			}
		}
	}

	public static void main(String[] args) throws AS400SecurityException, IOException, ErrorCompletingRequestException,
			InterruptedException, ObjectDoesNotExistException {
		// CABOT ACCUSYS run SBMJOB SBMJOB CMD(CALL PGM(PRUEBA) PARM("1"))
		// JOB(PRUEBA_JOB)
		// 172.28.194.101 CABOT ACCUSYS run SBMJOB SBMJOB CMD(CALL PGM(PRUEBA)
		// PARM("1"))
		//String[] array = new String[] { "172.28.194.101", "CABOT", "ACCUSYS", "run","SBMJOB CMD(CALL PGM(PRUEBA) PARM(\"1\")) JOB(PRUEBA_JOB)" };
		//String[] array = new String[] { "10.242.0.41", "PROBATCH", "lq330sde", "run","SBMJOB CMD(CALL PGM(OSDEPOSFIL/PGRALCFILR)) JOB(PGRALCFILR) JOBQ(QGPL/QBATCH) LOG(4 0 *SECLVL) LOGCLPGM(*YES)" };
		//args = array;
		if (args.length == 2 && args[0].equals("encrypt")) {
			do_encrypt(args[1]);
			System.exit(0);
		}

		if (args.length < 4) {
			usage();
		}

		String password = args[2];
		if (password.startsWith("!")) {
			try {
				password = decryptPassword(password.substring(1));
			} catch (Exception e) {
				System.err.println("Error al conectarse al AS400");
			}
		}
		AS400 sys = new AS400();

		try {
			sys.setGuiAvailable(false);
			sys.setSystemName(args[0]);
			sys.setUserId(args[1]);
			sys.setPassword(password);
		} catch (Exception e) {
			System.err.println("Error al conectarse al AS400");
			System.err.println("Sistema:  " + args[0]);
			System.err.println("Usuario:  " + args[1]);
			System.err.println("Password: " + password);

			e.printStackTrace();

			System.exit(1);
		}

		String op = args[3];

		if (op.equals("run2") && args.length == 5) {
			System.exit(do_run(sys, args[4]));
		} else if (op.equals("run") && args.length == 5) {
			System.out.println("entra a la invocacion del procesos do_run_mon");
			System.out.println("Salida o resultado de la ejecucion del proiceso do_run_mon -->>> "+do_run_mon(args, args[4])); 
		} else if (op.equals("version") && args.length == 4) {
			do_version(sys);
		} else if (op.equals("read") && args.length == 5) {
			do_read(sys, args[4]);
		} else if (op.equals("readseq") && args.length == 5) {
			do_readseq(sys, args[4]);
		} else if (op.equals("dir") && args.length == 6) {
			do_dir(sys, args[4], args[5]);
		} else if (op.equals("jobs") && args.length == 6) {
			do_jobs(sys, args[4], args[5]);
		} else if (op.equals("ping") && args.length == 4) {
			do_ping(sys);
		} else if (op.equals("is_file") && args.length == 5) {
			do_is_file(sys, args[4]);
		} else if (op.equals("is_directory") && args.length == 5) {
			do_is_directory(sys, args[4]);
		} else if (op.equals("is_executable") && args.length == 5) {
			do_is_executable(sys, args[4]);
		} else if (op.equals("chk_file_list") && args.length >= 5) {
			String[] a = new String[args.length - 4];
			System.arraycopy(args, 4, a, 0, args.length - 4);
			do_chk_file_list(sys, a);
		} else if (op.equals("system_value") && args.length >= 5) {
			String[] a = new String[args.length - 4];
			System.arraycopy(args, 4, a, 0, args.length - 4);
			do_system_value(sys, a);
		} else {

			usage();
		}
		System.out.println("fin del proceso de invocacion a metodos");
		System.exit(0);
	}

	private static void usage() {
		System.err.println("ASRemote <sistema> <usuario> <password> run <comando>");
		System.err.println("                                     version");
		System.err.println("                                     read <archivo>");
		System.err.println("                                     readseq <archivo>");
		System.err.println("                                     dir <directorio> <mascara>");
		System.err.println("                                     ping");
		System.err.println("                                     is_file <archivo>");
		System.err.println("                                     is_directory <archivo>");
		System.err.println("                                     is_executable <archivo>");
		System.err.println("                                     chk_file_list <archivo 1>..<archivo n>");
		System.err.println("                                     jobs <nombre_proceso> <usuario>");
		System.err.println("                                     system_value <valor 1>..<valor n>");
		System.err.println("         encrypt <password>");
		System.exit(1);
	}

	private static int do_run(AS400 sys, String command) throws AS400SecurityException, IOException,
			ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException {
		sys.connectService(2);

		AS400 sys_mon = new AS400(sys);
		sys_mon.connectService(2);

		CommandCall cmd = new CommandCall(sys, command);

		Job job = cmd.getServerJob();
		byte[] internalJobIdentifier = (byte[]) job.getValue(11007);
		Job job_mon = new Job(sys_mon, internalJobIdentifier);

		JobLog jlog_mon = job_mon.getJobLog();
		RunCommand rc = new RunCommand(cmd);

		Thread t = new Thread(rc);

		Thread hook = new ShutdownThread(job, job_mon);

		Runtime.getRuntime().addShutdownHook(hook);
		t.start();
		byte[] last = null;

		while (t.isAlive()) {

			jlog_mon.setStartingMessageKey(last);

			Enumeration<?> messageList = jlog_mon.getMessages();

			if (last != null) {
				messageList.nextElement();
			}

			while (messageList.hasMoreElements()) {

				QueuedMessage message = (QueuedMessage) messageList.nextElement();
				printMessage(message);
				last = message.getKey();
			}

			Thread.sleep(500L);
		}

		t.join();

		try {
			Runtime.getRuntime().removeShutdownHook(hook);
		} catch (IllegalStateException illegalStateException) {
		}

		JobLog jlog = job.getJobLog();
		jlog.setStartingMessageKey(last);

		Enumeration<?> messageList = jlog.getMessages();

		if (messageList.hasMoreElements()) {
			messageList.nextElement();
		}
		while (messageList.hasMoreElements()) {

			QueuedMessage message = (QueuedMessage) messageList.nextElement();
			printMessage(message);
		}

		if (rc.sucessfulExecution()) {
			return 0;
		}
		return 1;
	}

	private static int do_run_mon(String[] args, String command) throws AS400SecurityException, IOException,
			ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException {
		AS400 as400 = new AS400(args[0], args[1], args[2]);
		String mensaje = "";

		CommandCall cmd = new CommandCall(as400);
		try {
			// Ejecute el comando "CRTLIB FRED
			if (cmd.run(command) != true) {
				System.err.println("Error en ejecución de comando!");
			}
			// Muestra los mensajes (devueltos si hubo o no un error)
			AS400Message[] messagelist = cmd.getMessageList();
			for (int i = 0; i < messagelist.length; i++) {
				// impresión de mensaje
				mensaje = messagelist[i].getText();
				log(mensaje);
			}
		} catch (Exception e) {
			System.err.println("Command " + cmd.getCommand() + " did not run!");
		}

		int resp = monitor(mensaje, as400);
		as400.disconnectAllServices();
		log("done!");
		return resp;
		

	}

	private static int monitor(String datos, AS400 as400) {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
			String[] jobData = datos.split(" ")[1].split("/");
			Boolean flag = Boolean.FALSE;
			String status = "";
			do {	
				JobList jobList = new JobList(as400);
				// Filtra la lista de trabajos activos

				jobList.addJobSelectionCriteria(JobList.SELECTION_JOB_NUMBER, jobData[0].trim());
				jobList.addJobSelectionCriteria(JobList.SELECTION_USER_NAME, jobData[1].trim());
				jobList.addJobSelectionCriteria(JobList.SELECTION_JOB_NAME, jobData[2].trim());

				// Obtenga la lista de trabajos activos.
				Enumeration list;
				list = jobList.getJobs();
				// Para cada trabajo de la lista...
				while (list.hasMoreElements()) {
					Job j = (Job) list.nextElement();
					String ISOJobActiveDate = sdf.format(j.getDate());
					Date jobEndedDate = j.getJobEndedDate();
					String ISOJobEndedDate = (jobEndedDate == null) ? "NULL" : sdf.format(jobEndedDate);

					if (j.getStatus().trim().contentEquals(Job.JOB_STATUS_ACTIVE)) {
						flag = Boolean.TRUE;
					} else {
						if (j.getStatus().trim().equals(Job.JOB_STATUS_OUTQ)) {
							status = "";
							status = j.getStatus().trim();
							String estadoFinal = new String();
							String completionStatus = j.getCompletionStatus();
							String txtCompletionStatus = "NOT_COMPLETED";
							if (completionStatus.equals("0")) {
								txtCompletionStatus = "COMPLETED_NORMALLY";
							} else if (completionStatus.equals("1")) {
								txtCompletionStatus = "COMPLETED_ABNORMALLY";
							}
							status = String.valueOf(status) + "/" + txtCompletionStatus;
							if (status.contentEquals("")) {
								flag = Boolean.TRUE;
							} else {
								flag = Boolean.FALSE;
								log("{NumeroDeJob : " + j.getNumber() + " Nombre : " + j.getName().trim() + ","
										+ " Usuario : " + j.getUser().trim() + "," + " Status : " + status.toString()
										+ "," + " FechaActivo : " + ISOJobActiveDate + "," + " FechaFin : "
										+ ISOJobEndedDate + "}");
								return 0;
							}

						} else {
							flag = Boolean.TRUE;
							System.err.println("As400CmdRun:Error status no es "+Job.JOB_STATUS_OUTQ+".");
						}

					}
				}
				 Thread.sleep(1000L);
			} while (flag);

		} catch (Exception e) {
			System.err.println("failed");
			e.printStackTrace();
			System.err.println(e);
		}
		return 1;
	}

	private static void log(String s) {
		System.out.println("As400CmdRun:" + s);
	}

	private static void do_version(AS400 sys) {
		try {
			System.out.println("OS: V" + sys.getVersion() + "R" + sys.getRelease() + "M" + sys.getModification());
		} catch (AS400SecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void do_read(AS400 sys, String fileName) {
		try {
			IFSFile file = new IFSFile(sys, fileName);

			if (!file.exists()) {
				System.out.println("no existe");

				return;
			}
			System.out.printf("%s %s %d %s\n", new Object[] { file.isDirectory() ? "d" : " ", file.getName(),
					Long.valueOf(file.getOwnerUID()), file.getSubtype() });
			if (!file.canRead()) {
				System.out.println("no puedo leer");

				return;
			}

			BufferedReader reader = new BufferedReader(new IFSFileReader(file));

			String line;

			while ((line = reader.readLine()) != null) {
				System.out.println(line);
			}
			reader.close();
		} catch (Exception e) {

			System.out.println("Error occurred attempting to display the file.");
			e.printStackTrace();
		}
	}

	private static void do_readseq(AS400 sys, String fileName) {
		try {
			SequentialFile file = new SequentialFile(sys, fileName);
			AS400FileRecordDescription recordDescription = new AS400FileRecordDescription(sys, fileName);
			RecordFormat[] format = recordDescription.retrieveRecordFormat();
			file.setRecordFormat(format[0]);
			file.open(0, 100, 3);
			System.out.println("Displaying file " + fileName);

			Record record;
			while ((record = file.readNext()) != null) {

				Object[] fields = record.getFields();
				for (int i = 0; i < fields.length; i++) {
					System.out.print(fields[i] + "(" + fields[i].getClass().getSimpleName() + ")|");
				}
				System.out.println();
			}

			System.out.println();
			file.close();
		} catch (Exception exception) {
		}
	}

	private static void do_dir(AS400 sys, String directoryName, String pattern) {
		try {
			IFSFile directory = new IFSFile(sys, directoryName);

			Enumeration<?> directoryFiles = directory.enumerateFiles(pattern);

			while (directoryFiles.hasMoreElements()) {
				IFSFile f = (IFSFile) directoryFiles.nextElement();

				System.out.printf("%c%c %s ON:%s legnth:%d\n", new Object[] {
						// Character.valueOf(f.isDirectory() ? 100 : 32),
						// Character.valueOf(f.isFile() ? 102 : 32),
						f.getName(), f.getOwnerName(), Long.valueOf(f.length()) });
			}

		} catch (Exception e) {

			System.out.println("List failed");
			System.out.println(e);
		}
	}

	private static void do_jobs(AS400 sys, String job_name, String user_name) {
		try {
			JobList jobList = new JobList(sys);

			jobList.addJobSelectionCriteria(1, job_name);
			jobList.addJobSelectionCriteria(2, user_name);
			Enumeration<?> list = jobList.getJobs();
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

			while (list.hasMoreElements()) {
				Job j = (Job) list.nextElement();
				try {
					String status = j.getStatus();
					String ISOJobActiveDate = sdf.format(j.getJobActiveDate());
					Date jobEndedDate = j.getJobEndedDate();
					String ISOJobEndedDate = (jobEndedDate == null) ? "NULL" : sdf.format(jobEndedDate);

					if (status.equals("*ACTIVE")) {
						status = String.valueOf(status) + "/" + j.getValue(101);
					} else {
						String completionStatus = j.getCompletionStatus();
						String txtCompletionStatus = "NOT_COMPLETED";
						if (completionStatus.equals("0")) {
							txtCompletionStatus = "COMPLETED_NORMALLY";
						} else if (completionStatus.equals("1")) {
							txtCompletionStatus = "COMPLETED_ABNORMALLY";
						}
						status = String.valueOf(status) + "/" + txtCompletionStatus;
					}

					System.out.println(String.valueOf(j.getName()) + " " + j.getUser() + " " + j.getNumber() + " "
							+ status + " " + ISOJobActiveDate + " " + ISOJobEndedDate);
				} catch (Exception e) {
					System.out.println(" failed");
					e.printStackTrace();
					System.out.println(e);
				}

			}

		} catch (Exception e) {

			System.out.println("JobList failed");
			System.out.println(e);
		}
	}

	private static void do_is_file(AS400 sys, String fileName) {
		try {
			IFSFile file = new IFSFile(sys, fileName);
			if (file.isFile() || file.canExecute()) {
				System.out.println("true");
			} else {
				System.out.println("false");
			}
		} catch (Exception exception) {
		}
	}

	private static void do_is_directory(AS400 sys, String fileName) {
		try {
			IFSFile file = new IFSFile(sys, fileName);
			if (file.isDirectory()) {
				System.out.println("true");
			} else {
				System.out.println("false");
			}
		} catch (Exception exception) {
		}
	}

	private static void do_is_executable(AS400 sys, String fileName) {
		try {
			IFSFile file = new IFSFile(sys, fileName);
			if (file.canExecute()) {
				System.out.println("true");
			} else {
				System.out.println("false");
			}
		} catch (Exception exception) {
		}
	}

	private static void do_chk_file_list(AS400 sys, String[] a) {
		for (int i = 0; i < a.length; i++) {
			try {
				IFSFile file = new IFSFile(sys, a[i]);
				if (!file.isFile()) {
					System.out.println(a[i]);

				}

			} catch (Exception exception) {
			}
		}
	}

	private static void do_system_value(AS400 sys, String[] a) {
		for (int i = 0; i < a.length; i++) {
			try {
				SystemValue value = new SystemValue(sys, a[i]);
				System.out.println(value.getValue());
			} catch (Exception e) {
				System.out.println();
			}
		}
	}

	private static Key generateKey() throws Exception {
		byte[] keyValue = new byte[] { 66, -110, 39, -23, -105, 61, 26, 51, 48, -53, 34, 1, 118, 96, 76, 111 };
		return new SecretKeySpec(keyValue, "AES");
	}

	private static void do_encrypt(String password) {
		try {
			Key key = generateKey();
			Cipher c = Cipher.getInstance("AES");
			c.init(1, key);
			byte[] encVal = c.doFinal(password.getBytes());
			String encryptedValue = DatatypeConverter.printBase64Binary(encVal);
			System.out.println("!" + encryptedValue);
			System.out.println(decryptPassword(encryptedValue));
		} catch (Exception e) {
			System.err.println(e);
		}
	}

	private static String decryptPassword(String encryptedData) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance("AES");
		c.init(2, key);
		byte[] decodedValue = DatatypeConverter.parseBase64Binary(encryptedData);
		byte[] decValue = c.doFinal(decodedValue);
		return new String(decValue);
	}

	private static void printMessage(QueuedMessage message) {
		System.out.println(String.valueOf(message.getFromProgram()) + ":" + message.getAlertOption() + ":"
				+ message.getSeverity() + ":" + message.getText());
	}

	private static void do_ping(AS400 sys) {
		AS400JPing pingObj = new AS400JPing(sys.getSystemName(), 99, false);
		try {
			pingObj.setPrintWriter(System.out);
			pingObj.setTimeout(1000L);
		} catch (Exception exception) {
		}

		if (pingObj.ping()) {
			System.out.println("SUCCESS");
		} else {
			System.out.println("FAILED");
		}
	}

}
