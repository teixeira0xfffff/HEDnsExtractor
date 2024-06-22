package utils

import (
	"database/sql"
	"fmt"
	"strconv"

	//_ "github.com/mattn/go-sqlite3"
	"github.com/projectdiscovery/gologger"
	_ "modernc.org/sqlite"
)

type Report struct {
	Database string
	db       *sql.DB
}

func NewReport() *Report {
	database := "results.sqlite"
	db, err := sql.Open("sqlite", database)
	if err != nil {
		gologger.Error().Msgf("Error opening the database: %s", err)
		return nil
	}

	return &Report{
		Database: database,
		db:       db,
	}
}

func (r *Report) CreateTables() error {
	_, err := r.db.Exec("CREATE TABLE IF NOT EXISTS results (domain TEXT, ptr TEXT, ipaddr TEXT, vt_domain_score INTEGER DEFAULT 0, vt_ip_score INTEGER DEFAULT 0)")
	if err != nil {
		return err
	}
	return nil
}

func (r *Report) Import() {

	// Create the table if not exists
	err := r.CreateTables()
	if err != nil {
		gologger.Error().Msgf("Error creating the table: %s", err)
		return
	}

	for _, result := range Results {
		// check if the record exists
		var exists bool
		err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM results WHERE domain = ? AND ptr = ? AND ipaddr = ?)", result.Domain, result.PTR, result.IPAddr).Scan(&exists)
		if err != nil {
			gologger.Error().Msgf("Error querying the database: %s", err)
			return
		}

		if !exists {
			_, err := r.db.Exec("INSERT INTO results (domain, ptr, ipaddr) VALUES (?, ?, ?)", result.Domain, result.PTR, result.IPAddr)
			if err != nil {
				gologger.Error().Msgf("Error inserting into the database: %s", err)
				return
			}
		}
	}
}

func (r *Report) Enrich(VTEnable bool) {
	if VTEnable {
		// Enrich the domain
		r.EnrichVTDomain()

		// Enrich the IP
		r.EnrichVTIP()
	}
}

func (r *Report) EnrichVTDomain() {
	rows, err := r.db.Query("SELECT DISTINCT domain FROM results")
	if err != nil {
		gologger.Error().Msgf("Error querying the database: %s", err)
		return
	}

	// Iterate over the rows
	domains := make([]string, 0)
	for rows.Next() {
		var domain string
		err = rows.Scan(&domain)
		domains = append(domains, domain)
		if err != nil {
			gologger.Error().Msgf("Error scanning the row: %s", err)
			return
		}
	}

	virustotal := Virustotal{}
	for _, domain := range domains {
		// Get the VT score
		score := virustotal.GetVtReport(domain)
		_, err := r.db.Exec("UPDATE results SET vt_domain_score = ? WHERE domain = ?", score, domain)
		if err != nil {
			gologger.Error().Msgf("Error updating the database: %s", err)
			return
		}
	}
}

func (r *Report) EnrichVTIP() {
	rows, err := r.db.Query("SELECT DISTINCT ipaddr FROM results")
	if err != nil {
		gologger.Error().Msgf("Error querying the database: %s", err)
		return
	}

	// Iterate over the rows
	ipaddresses := make([]string, 0)
	for rows.Next() {
		var ipaddr string
		err = rows.Scan(&ipaddr)
		ipaddresses = append(ipaddresses, ipaddr)
		if err != nil {
			gologger.Error().Msgf("Error scanning the row: %s", err)
			return
		}
	}

	virustotal := Virustotal{}
	for _, ipaddr := range ipaddresses {
		// Get the VT score
		score := virustotal.GetVtReport(ipaddr)
		_, err := r.db.Exec("UPDATE results SET vt_ip_score = ? WHERE ipaddr = ?", score, ipaddr)
		if err != nil {
			gologger.Error().Msgf("Error updating the database: %s", err)
			return
		}
	}
}

func (r *Report) Show(VTEnable bool, VtScore string) {
	score, err := strconv.ParseUint(VtScore, 10, 64)
	if VTEnable && err != nil {
		gologger.Error().Msgf("Invalid parameter value for vt-score: %s", err)
		return
	}

	// if VTEnable the select for vt_domain_score must be greater than score
	// if VTEnable the select for vt_ip_score must be greater than score
	var stmt string
	if VTEnable {
		gologger.Info().Msgf("Showing results with VT score greater than %d", score)
		stmt = fmt.Sprintf("SELECT * FROM results WHERE vt_domain_score >= %d AND vt_ip_score >= %d", score, score)
	} else {
		stmt = "SELECT * FROM results"
	}

	// Query the database and print all rows
	rows, err := r.db.Query(stmt)
	if err != nil {
		gologger.Error().Msgf("Error querying the database: %s", err)
		return
	}

	// Iterate over the rows
	for rows.Next() {
		var domain, ptr, ipaddr string
		var vtDomainScore, vtIpScore int
		err = rows.Scan(&domain, &ptr, &ipaddr, &vtDomainScore, &vtIpScore)
		if err != nil {
			gologger.Error().Msgf("Error scanning the row: %s", err)
			return
		}

		gologger.Info().Msgf("Domain: %s, PTR: %s, IP: %s, VT Domain Score: %d, VT IP Score: %d", domain, ptr, ipaddr, vtDomainScore, vtIpScore)
	}
}

func (r *Report) Close() {
	// Close the database
	defer r.db.Close()
}
