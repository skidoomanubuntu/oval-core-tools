#!/bin/env python3

from bs4 import BeautifulSoup
import shutil, subprocess, os, requests, bz2, time
from datetime import datetime
from snap_manifest import main as refreshManifests

# This updates files if necessary
def updateFiles(version):
	def downloadFile(url, file):
		# Can I download it?
		try:
			response = requests.get(url)
			if os.path.isfile(file):
				os.remove(file)
			open("%s" % file, 'wb').write(bz2.decompress(response.content))
			if not os.path.isfile(file):
				return False
			return True
		except Exception as e:
			print (e)
			return False


	def getFile(filename):
		# Is the file present?
		if (os.path.isfile(filename)):
			# Has it been updated within the last 24 hours?
			if (time.time() - os.path.getmtime(filename) < 86400):
				print ("%s exists and has been updated during last 24 hours" % filename)
				return True
			else:
				if not downloadFile('https://security-metadata.canonical.com/oval/%s.bz2' % filename, filename):
					print ("%s could not be retrieved, but there is an old copy locally, analysis will still proceed" % filename)
		else:
			if not downloadFile('https://security-metadata.canonical.com/oval/%s' % filename, filename):
				print ("%s could not be retrieved, and there is no local copy, analysis will stop" % filename)
				return False
		return True
				
	# We have two files to update
	# oci.com.ubuntu.[version].pkg.oval.xml
	# oci.com.ubuntu.[version].usn.oval.xml
	pkgFile = "oci.com.ubuntu.%s.pkg.oval.xml" % version
	usnFile = "oci.com.ubuntu.%s.usn.oval.xml" % version
	cveFile = "com.ubuntu.%s.cve.oval.xml" % version
	return (getFile(pkgFile) and getFile(usnFile) and getFile(cveFile))

# Analyze the output from command
# oscap oval eval --results report.xml oci.com.ubuntu.[version].usn.oval.xml
# in presence of the proper manifest file
def analyzeOscapOciReport(filename):
	usnMap = {}
	resultMap = {}
	xmlFile = open(filename, 'r')
	contents = xmlFile.read()
	soup = BeautifulSoup(contents, 'xml')
	results = soup.find('results')
	definitions = soup.find('definitions')
	defs = definitions.find_all('definition')

	resultDefs = results.find_all('definition')
	for result in resultDefs:
		resultMap[result['definition_id']] = result['result']

	for definition in defs:
		title = definition.find('title').text
		parts = title.split(' -- ')
		severity = definition.find('severity').text
		cves = []
		for cve in definition.find_all('cve'):
			cves.append(cve.text)
		usnMap[parts[0]]= {'id':definition['id'], 
			'result': resultMap[definition['id']],
			'severity': severity, 'cve':cves}

	return usnMap


# This function takes the dictionary we generated from an oscap report
# and then compiles the stats according to severity
def generateData(dict):
	results = { 'Critical': {'fixed':0, 'present':0},
			'High': {'fixed':0, 'present':0},
			'Medium': {'fixed':0, 'present':0},
			'Low': {'fixed':0, 'present': 0},
			'Other': {'fixed':0, 'present': 0} }
	for data in dict.values():
		key = 'Other'
		if data['severity'] in results.keys():
			key = data['severity']
		if data['result'] == 'true':
			results[key]['present'] += 1
		else:
			results[key]['fixed'] +=1
	#print (results)
	return results

# This function takes all the individual oscap dictionaries and ensures that all the usn entries
# are compressed to one, independently of the kernel they compare to
# We want to keep only one USN entry
def getTotals(dicts):
	total = {}
	for dict in dicts.values():
		for usn in dict.keys():
			if usn in total.keys():
				# Duplicate, do we need to update the values? Do so only if result==true
				# This way, if some of these entries are fixed and others not, we want to be
				# biased toward "not fixed"
				if dict[usn]['result'] == 'true':
					total[usn] = dict[usn]
			else:
				total[usn] = dict[usn]
	return total

# This function takes a mapping of all the USNs we have and compiles unique dict of CVE 
# Value indicates if the problem may still be present (true)
def getCVETotalsFromUSNs(dict):
	cves = {}
	for usns in dict.values():
		for usn in usns.keys():
			for cve in usns[usn]['cve']:
				if usns[usn]['result'] == 'true':
					cves[cve] = True
				elif cve not in cves.keys():
					cves[cve] = False
	return cves

# This function generates an HTML report that is essentially a table
# showing the vulnerabilities + fixed metrics
def generateUSNStats(dicts, filename, totals):
	def printResultLine(dict):
		myString = ""
		for key in dict.keys():
			total = int(dict[key]['fixed']) + int(dict[key]['present'])
			fixed = int(dict[key]['fixed'])
			percentage = 0
			try:
				percentage = '%.1f%%' % (100 * fixed/total)
			except ZeroDivisionError:
				percentage = '-'
			myString += "<td><font color='grey'><b>%s</b></font><br>%s fixed (%s)</td>" % (total, fixed, percentage)
		return myString

	with open(filename, 'w') as htmlFile:
		#svg = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path fill-rule="evenodd" clip-rule="evenodd" d="M11.0738 3.0246C10.1673 2.72243 9.14268 2.04756 8 1C7.04053 1.98649 6.0124 2.66253 4.91563 3.02812C3.81885 3.39372 2.84698 3.38434 2 3L2.58477 9.01727C2.81947 11.8337 7 15 8 15L8.22808 14.9953C8.89351 14.9677 13.1869 11.7576 13.4152 9.01727L14 3C12.9557 3.31857 11.9803 3.32677 11.0738 3.0246ZM7.91889 3.08225L8.031 2.991L8.14723 3.08114C8.99972 3.72847 9.81311 4.18551 10.5995 4.44762L10.8808 4.53358C11.2578 4.63839 11.642 4.70402 12.0323 4.73106L12.323 4.744L11.9223 8.87218L11.9036 9.01558C11.7672 9.79921 11.0439 10.8781 9.94163 11.9464C9.44337 12.4293 8.90405 12.8742 8.43048 13.2037L8.31427 13.283C8.2391 13.3334 8.16875 13.3784 8.10468 13.4176L8.035 13.458L8.00489 13.4441C7.88312 13.3844 7.73462 13.3002 7.56968 13.1954C7.09092 12.891 6.54589 12.461 6.04049 11.9792L5.82924 11.7724C4.79787 10.736 4.144 9.66559 4.07959 8.8927L3.68 4.787L4.03684 4.75824C4.47846 4.70726 4.93023 4.6044 5.38997 4.45115C6.28031 4.15437 7.12373 3.696 7.91889 3.08225Z"/></svg>'
		htmlFile.write('<table border="0" width="100%" padding="3" spacing="10">\n')
		htmlFile.write('   <tr>\n')
		htmlFile.write("       <th style='background-color: #111;' width='100%'><h2><img src='security.svg' height='30'>&nbsp;&nbsp;USN on the system & fixes (Beta)</h2></th>\n")
		htmlFile.write('   </tr><tr><td valign="top">\n')
		htmlFile.write('      <div class="tableFixHead">')
		htmlFile.write('      <table border="0" width="100%">')
		htmlFile.write('<thead> <tr>')
		htmlFile.write('      <th>Source</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Other</th>\n')
		htmlFile.write('   </tr></thead><tbody><tr>\n')
		htmlFile.write('      <td><b>Total</b></td>%s\n' % printResultLine(totals))
		htmlFile.write('   </tr>\n')
		for version in dicts.keys():
			htmlFile.write('   <tr>\n')
			htmlFile.write('      <td><b>%s</b></td>%s\n' % (version, printResultLine(dicts[version])))
			htmlFile.write('   </tr>\n')
		htmlFile.write('</tbody></table></td></tr>')
		htmlFile.write('<tr><td colspan="6" style="background-color: #111;" width="100%"><h3><center>Last updated on ' + datetime.now().strftime("%Y-%m-%d %H:%M") + '</center></h3></td></tr></table>' )

def analyzeCVEFile(filename, dict):
	print ("Indexing CVEs in %s" % filename)
	xmlFile = open(filename, 'r')
	contents = xmlFile.read()
	soup = BeautifulSoup(contents, 'lxml')
	definitions_meta = soup.find('definitions')
	# For each definition
	classes = []
	definitions = definitions_meta.find_all("definition")
	
	for definition in definitions:
		if definition['class'][0] == 'vulnerability':
			title = definition.find('title').text.split(' ')[0]
			description = definition.find('description').text
			severity = definition.find('severity').text
			date = definition.find('public_date').text
			dict[title] = {"title":title, "description":description, "severity": severity, "date": date}
	return dict

# This function takes a list of CVEs that are relevant, then looks them up in a dict
# It then generates a table of CVEs that have been taken care of
def generateCVEStats(relevant_cves, cve_info, filename):
	severity_stats = {'critical':0, 'high':0, 'medium':0, 'low':0, 'negligible':0}
	for cve in relevant_cves:
		try:
			severity_stats[cve_info[cve]['severity'].lower()] += 1
		except:
			print ('Skipping %s' % cve)

	with open(filename, 'w') as htmlFile:
		htmlFile.write('<table border="0" width="100%" padding="3" spacing="10">\n')
		htmlFile.write('   <tr>\n')
		htmlFile.write("       <th style='background-color: #111;' width='100%'><h2><img src='security.svg' height='30'>&nbsp;&nbsp;CVEs this system is protected against (Beta)</h2></th>\n")
		htmlFile.write('   </tr><tr><td valign="top">\n')
		htmlFile.write('      <div class="tableFixHead">')
		htmlFile.write('      <table border="0" width="100%">')
		htmlFile.write('<thead> <tr>')
		htmlFile.write('      <th><h3>Critical</h3></th><th><h3>High</h3></th><th><h3>Medium</h3></th><th><h3>Low</h3></th>\n')
		htmlFile.write('   </tr></thead>\n')
		htmlFile.write('   <tbody><tr>\n')
		htmlFile.write('   <td align="center"><h3>%s</h3></td><td align="center"><h3>%s</h3></td><td align="center"><h3>%s</h3></td><td align="center><h3>%s</h3></td>' % (severity_stats['critical'], severity_stats['high'], severity_stats['medium'], severity_stats['low'], severity_stats['negligible']))
		htmlFile.write('</tbody></table></td></tr>')
		htmlFile.write('<tr><td colspan="6" style="background-color: #111;" width="100%"><h3><center>Last updated on ' + datetime.now().strftime("%Y-%m-%d %H:%M") + '</center></h3></td></tr></table>' )
		
		'''htmlFile.write('<table border="0" width="100%" padding="3" spacing="10">\n')
		htmlFile.write('   <tr>\n')
		htmlFile.write("       <th style='background-color: #111;' width='100%'><h2><img src='security.svg' height='30'>&nbsp;&nbsp;USN on the system & fixes</h2></th>\n")
		htmlFile.write('   </tr><tr><td valign="top">\n')
		htmlFile.write('      <div class="tableFixHead">')
		htmlFile.write('      <table border="0" width="100%">')
		htmlFile.write('<thead> <tr>')
		htmlFile.write('      <th>CVE</th><th>Severity</th><th>Date</th>\n')
		htmlFile.write('   </tr></thead>\n')
		htmlFile.write('   <tbody>\n')
		for cve in relevant_cves:
			try:
				mickey = cve_info[cve]
				htmlFile.write('   <tr>\n')
				#print (cve_info[cve])
				htmlFile.write('      <td><b>%s</b></td><td>%s</td><td>%s</td>\n' % (cve, cve_info[cve]['severity'], cve_info[cve]['date']))
				htmlFile.write('   </tr>\n')
			except Exception:
				print ('skipped CVE %s' % cve)
				pass
		htmlFile.write('</tbody></table></td></tr>')
		htmlFile.write('<tr><td colspan="6" style="background-color: #111;" width="100%"><h3><center>Last updated on ' + datetime.now().strftime("%Y-%m-%d %H:%M") + '</center></h3></td></tr></table>' )
		'''

'''# This takes an OCI PCK file and returns a dictionary as follows:
# Package -> {{usn->[cve]}, component}
def analyzePkgFile(filename):
	# At this point in time, the file manifest should be relative to the version we selected
	# This file lists all packages used (last column)
	# We need that info to limit the size of our pkgMap to what is relevant to us
	relevantPkg = []
	with open('manifest', 'r') as manifestFile:
		lines = manifestFile.readlines()
		for line in lines:
			columns = line.replace('\n','').split(' ')
			relevantPkg.append(columns[0])
	pkgMap = {}
	xmlFile = open(filename, 'r')
	contents = xmlFile.read()
	soup = BeautifulSoup(contents, 'xml')
	definitions = soup.find_all('definitions')
	for definition in definitions:
		package = definition.find('title').text
		if not package in relevantPkg:
			continue
		component = definition.find('component').text
		usn = {}
		for cve in definition.find_all('cve'):
			if 'usns' in cve.attrs.keys():
				for usnEntry in cve['usns'].replace(' ','').split(','):
					if usnEntry in usn.keys():
						usn[usnEntry].append(cve.text)
					else:
						usn[usnEntry] = [cve.text]

		pkgMap[package] = {'usn':usn, 'component':component}

	return pkgMap

# This takes a pkg file and turns it into the following dict:
# usn -> component
def analyzePkgFileFromUsn(filename):	
	pkgMap = {}
	xmlFile = open(filename, 'r')
	contents = xmlFile.read()
	soup = BeautifulSoup(contents, 'xml')
	definitions = soup.find_all('definitions')
	for definition in definitions:
		package = definition.find('title').text
		component = definition.find('component').text
		for cve in definition.find_all('cve'):
			if 'usns' in cve.attrs.keys():
				for usnEntry in cve['usns'].replace(' ','').split(','):
					if usnEntry in pkgMap.keys() and pkgMap[usnEntry] != component:
						print ('%s is affecting two components: %s, %s' % (usnEntry, pkgMap[usnEntry], component))
					else:
						pkgMap[usnEntry] = component

	return pkgMap


# This takes a pkg file and turns it into the following dict:
# cve -> [{package, [component]}]
def analyzeComponents(filename):	
	cveMap = {}
	xmlFile = open(filename, 'r')
	contents = xmlFile.read()
	soup = BeautifulSoup(contents, 'xml')
	definitions = soup.find_all('definitions')
	for definition in definitions:
		package = definition.find('title').text
		component = definition.find('component').text
		for cve in definition.find_all('cve'):
			if cve.text in cveMap.keys():
				found = False
				for entry in cveMap[cve.text]:
					if entry['package'] == package:
						if not component in entry['component']:
							entry['component'].append(component)
						found = True
						break
				if not found:
					cveMap[cve.text].append({'package':package, 'component':[component]})
			else:
				cveMap[cve.text] = [{'package':package, 'component':[component]}]

	return cveMap

# This cross-references two maps to associate fixes and components:
def crossReferenceUsnComponents(oscap, pkg):
	resultMap = {'main':{'fixed':0, 'present':0}, 
			'universe':{'fixed':0, 'present':0}, 
			'multiverse':{'fixed':0, 'present':0},
			'other':{'fixed':0, 'present':0}}

	for entry in oscap.keys():
		# Entry is USN- prefixed. Our pkg file does not have this prefix
		# Adjust
		entry = entry[4:]
		if not entry in pkg.keys():
			print ("%s could not be found in pkg map" % entry)
		else:
			dict = None
			if pkg[entry] == 'main':
				dict = resultMap['main']
			elif pkg[entry] == 'universe':
				dict = resultMap['universe']
			elif pkg[entry] == 'multiverse':
				dict = resultMap['multiverse']
			else:
				dict = resultMap['other']
			if oscap['USN-%s' % entry]['result'] == 'true':
				dict['present'] += 1
			else:
				dict['fixed'] += 1
	return resultMap

# This cross-references two maps to associate fixes and components:
def crossReferenceComponents(oscap, pkg):
	resultMap = {'main':{'fixed':0, 'present':0}, 
			'universe':{'fixed':0, 'present':0}, 
			'multiverse':{'fixed':0, 'present':0},
			'other':{'fixed':0, 'present':0}}

	# Interim map: cve-> {component-> result}
	interimMap = {}

	for entry in oscap.values():
		result = entry['result']
		for cve in entry['cve']:
			if not cve in pkg.keys():
				#print ("ERROR: %s not found in pkg keys" % (cve))
				# Shove them straight to Others
				if result == 'true':
					resultMap['other']['fixed'] += 1
				else:
					resultMap['other']['fixed'] += 1
				continue
			# If 1 result is true, then bug is still present
			if cve in interimMap.keys():
				for package in pkg[cve]:
					for component in package['component']:
						if component in interimMap[cve].keys():
							if result == 'true':
								interimMap[cve][component] = True
							else:
								pass # Should ensure 1 CVE answer, and True by default
						else:
							# New component
							if result == 'true':
								interimMap[cve][component] = True
							else:
								interimMap[cve][component] = False
			else:
				# New CVE
				interimMap[cve] = {}
				for package in pkg[cve]:
					for component in package['component']:
						if result == 'true':
							interimMap[cve][component] = True
						else:
							interimMap[cve][component] = False
		
	# Now that we have an interim map, score the results
	for entry in interimMap.values():
		for component in entry.keys():
			if entry[component]:
				resultMap[component]['present'] += 1
			else:
				resultMap[component]['fixed'] += 1

	return resultMap
'''

class Logger:
	def __init__(self):
		print ('logger reset')
		self.filePtr = open('log', 'w')
		self.filePtr.close()

	def write(self, msg):
		self.filePtr = open('log', 'a')
		print ('LOG: %s' % msg)
		self.filePtr.writelines('%s\n' % msg)
		self.filePtr.close()

if __name__ == "__main__":
	print ("Security scan executing from %s" % os.getcwd())
	versions = {'core18':'bionic', 'core20':'focal', 'core22':'jammy', 'snapd':'xenial', 'pc-kernel': 'jammy'}
	cves = {}
	maps = {}
	results = {}
	components = {}
	logger = Logger()

	# Run this if the manifests files are either non-existent or older than 24 hours
	for key in versions.keys():
		if not os.path.exists('manifest.%s' % key) or (time.time() - os.path.getmtime('manifest.%s' % key) > 8640):
			logger.write('Refreshing manifest files')
			refreshManifests()
			break

	for version in versions.keys():
		# Ensure we have the files we need
		if not updateFiles(versions[version]):
			logger.write("Could not update files for version %s, analysis for this version will be skipped" % version)
			continue

		cves = analyzeCVEFile("com.ubuntu.%s.cve.oval.xml" % versions[version], cves)
		print (cves)
		# First, make sure that the right manifest file gets copied as manifest
		shutil.copy('manifest.%s' % version, 'manifest')
		
		# Run the oscap tool
		output = subprocess.run(['oscap', 'oval', 'eval', '--results', 'report_%s.xml' % version, 'oci.com.ubuntu.%s.usn.oval.xml' % versions[version]], stderr=subprocess.PIPE)	
		logger.write('oscap stderr: %s' % output.stderr)
		

		# You should now have a report_[version].xml report to send for analysis
		if os.path.exists('report_%s.xml' % version):
			logger.write('analyzing Oscap OCI')
			maps[version] = analyzeOscapOciReport('report_%s.xml' % version)
			logger.write('generating data')
			results[version] = generateData(maps[version])
			''' Reactivate when (if) we can (or should) resume work on components (main, universe, etc).
			Code works but doesn't tell us something particularly helpful - probably the wrong analysis
			components[version] = crossReferenceComponents(maps[version], analyzeComponents('oci.com.ubuntu.%s.pkg.oval.xml' % versions[version]))
			print (components[version])'''
			

			#componentsMap = crossReferenceUsnComponents(maps[version], analyzePkgFileFromUsn('oci.com.ubuntu.%s.pkg.oval.xml' % versions[version]))
			#print (componentsMap)
		else:
			print ('File report_%s.xml was not created by the oscap tool, analysis incomplete')
			break

	# Generate totals
	totals = generateData(getTotals(maps))
	generateUSNStats(results, 'usn_stats.php', totals)

	# Generate CVE list
	relevant_cves = getCVETotalsFromUSNs(maps)

	# Keep only the CVes that are not present - trash all others
	final_list = []
	for entry in relevant_cves.keys():
		if not relevant_cves[entry]:
			final_list.append(entry)

	generateCVEStats(final_list, cves, "cve_stats.php")

	#print (maps)

	#for entry in components.keys():
	#	print ("%s: %s" % (entry, components[entry]))
