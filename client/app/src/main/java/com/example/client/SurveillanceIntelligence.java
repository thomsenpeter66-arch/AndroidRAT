package com.example.client;

import android.location.Location;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Advanced Intelligence Collection and Behavioral Analysis System
 * Provides comprehensive target profiling and behavioral pattern analysis
 */
public class SurveillanceIntelligence {

    private static final String TAG = "SurveillanceIntelligence";
    
    // Movement and Location Intelligence
    private List<LocationDataPoint> locationHistory;
    private Map<String, Integer> locationFrequency; // Common locations
    private double totalDistanceTraveled;
    private double averageSpeed;
    
    // Temporal Behavior Analysis
    private Map<Integer, ActivityPattern> hourlyActivity; // Activity by hour
    private Map<Integer, ActivityPattern> dailyActivity; // Activity by day of week
    
    // Communication Patterns
    private Map<String, ContactPattern> contactPatterns;
    private Map<String, Integer> appUsagePatterns;
    
    // Environmental Context
    private List<EnvironmentalContext> environmentalHistory;
    
    // Behavioral Metrics
    private BehavioralMetrics behavioralMetrics;
    
    public SurveillanceIntelligence() {
        initializeIntelligenceCollectors();
    }
    
    private void initializeIntelligenceCollectors() {
        locationHistory = new ArrayList<>();
        locationFrequency = new ConcurrentHashMap<>();
        hourlyActivity = new ConcurrentHashMap<>();
        dailyActivity = new ConcurrentHashMap<>();
        contactPatterns = new ConcurrentHashMap<>();
        appUsagePatterns = new ConcurrentHashMap<>();
        environmentalHistory = new ArrayList<>();
        behavioralMetrics = new BehavioralMetrics();
        
        // Initialize hourly activity patterns (0-23 hours)
        for (int i = 0; i < 24; i++) {
            hourlyActivity.put(i, new ActivityPattern());
        }
        
        // Initialize daily activity patterns (1-7 days, Sunday = 1)
        for (int i = 1; i <= 7; i++) {
            dailyActivity.put(i, new ActivityPattern());
        }
    }
    
    /**
     * Update movement and location intelligence
     */
    public void updateMovementData(Location location, float distance, float speed) {
        try {
            // Create location data point
            LocationDataPoint dataPoint = new LocationDataPoint(
                location.getLatitude(),
                location.getLongitude(),
                location.getAccuracy(),
                speed,
                distance,
                System.currentTimeMillis()
            );
            
            locationHistory.add(dataPoint);
            
            // Update travel metrics
            totalDistanceTraveled += distance;
            updateAverageSpeed(speed);
            
            // Analyze location frequency (round to ~100m grid)
            String locationKey = String.format("%.3f,%.3f", 
                Math.round(location.getLatitude() * 1000.0) / 1000.0,
                Math.round(location.getLongitude() * 1000.0) / 1000.0);
            
            locationFrequency.put(locationKey, locationFrequency.getOrDefault(locationKey, 0) + 1);
            
            // Update temporal activity patterns
            updateTemporalPatterns(location);
            
            // Analyze movement patterns
            analyzeMobilityPatterns(dataPoint);
            
            // Cleanup old data (keep last 1000 points)
            if (locationHistory.size() > 1000) {
                locationHistory.remove(0);
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Error updating movement data", e);
        }
    }
    
    /**
     * Update contact and communication patterns
     */
    public void updateContactPattern(String identifier, String type, long timestamp) {
        try {
            ContactPattern pattern = contactPatterns.getOrDefault(identifier, new ContactPattern(identifier));
            pattern.addContact(type, timestamp);
            contactPatterns.put(identifier, pattern);
        } catch (Exception e) {
            Log.e(TAG, "Error updating contact pattern", e);
        }
    }
    
    /**
     * Update app usage patterns
     */
    public void updateAppUsage(String packageName, long duration) {
        try {
            appUsagePatterns.put(packageName, appUsagePatterns.getOrDefault(packageName, 0) + (int)duration);
        } catch (Exception e) {
            Log.e(TAG, "Error updating app usage", e);
        }
    }
    
    /**
     * Update environmental context data
     */
    public void updateEnvironmentalContext(String context, Object value, long timestamp) {
        try {
            EnvironmentalContext envContext = new EnvironmentalContext(context, value, timestamp);
            environmentalHistory.add(envContext);
            
            // Cleanup old environmental data (keep last 500 entries)
            if (environmentalHistory.size() > 500) {
                environmentalHistory.remove(0);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error updating environmental context", e);
        }
    }
    
    /**
     * Generate comprehensive behavioral profile
     */
    public JSONObject generateBehavioralProfile() throws JSONException {
        JSONObject profile = new JSONObject();
        
        // Movement and location analysis
        profile.put("location_analysis", generateLocationAnalysis());
        
        // Temporal behavior analysis
        profile.put("temporal_analysis", generateTemporalAnalysis());
        
        // Communication analysis
        profile.put("communication_analysis", generateCommunicationAnalysis());
        
        // Mobility patterns
        profile.put("mobility_patterns", generateMobilityAnalysis());
        
        // Environmental preferences
        profile.put("environmental_analysis", generateEnvironmentalAnalysis());
        
        // Risk assessment
        profile.put("risk_assessment", generateRiskAssessment());
        
        // Behavioral metrics
        profile.put("behavioral_metrics", behavioralMetrics.toJSON());
        
        profile.put("profile_generated", System.currentTimeMillis());
        profile.put("data_points", locationHistory.size());
        
        return profile;
    }
    
    private JSONObject generateLocationAnalysis() throws JSONException {
        JSONObject analysis = new JSONObject();
        
        // Most frequent locations
        JSONArray frequentLocations = new JSONArray();
        locationFrequency.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(entry -> {
                try {
                    JSONObject location = new JSONObject();
                    String[] coords = entry.getKey().split(",");
                    location.put("latitude", Double.parseDouble(coords[0]));
                    location.put("longitude", Double.parseDouble(coords[1]));
                    location.put("visit_count", entry.getValue());
                    frequentLocations.put(location);
                } catch (Exception e) {
                    Log.e(TAG, "Error processing frequent location", e);
                }
            });
        
        analysis.put("frequent_locations", frequentLocations);
        analysis.put("total_distance_traveled", totalDistanceTraveled);
        analysis.put("average_speed", averageSpeed);
        analysis.put("unique_locations_visited", locationFrequency.size());
        
        return analysis;
    }
    
    private JSONObject generateTemporalAnalysis() throws JSONException {
        JSONObject analysis = new JSONObject();
        
        // Hourly activity patterns
        JSONObject hourlyPatterns = new JSONObject();
        for (Map.Entry<Integer, ActivityPattern> entry : hourlyActivity.entrySet()) {
            hourlyPatterns.put(entry.getKey().toString(), entry.getValue().toJSON());
        }
        
        // Daily activity patterns
        JSONObject dailyPatterns = new JSONObject();
        for (Map.Entry<Integer, ActivityPattern> entry : dailyActivity.entrySet()) {
            dailyPatterns.put(entry.getKey().toString(), entry.getValue().toJSON());
        }
        
        analysis.put("hourly_patterns", hourlyPatterns);
        analysis.put("daily_patterns", dailyPatterns);
        analysis.put("most_active_hours", findMostActiveHours());
        analysis.put("most_active_days", findMostActiveDays());
        
        return analysis;
    }
    
    private JSONObject generateCommunicationAnalysis() throws JSONException {
        JSONObject analysis = new JSONObject();
        
        JSONArray topContacts = new JSONArray();
        contactPatterns.entrySet().stream()
            .sorted((e1, e2) -> Integer.compare(e2.getValue().getTotalContacts(), e1.getValue().getTotalContacts()))
            .limit(20)
            .forEach(entry -> {
                try {
                    topContacts.put(entry.getValue().toJSON());
                } catch (Exception e) {
                    Log.e(TAG, "Error processing contact pattern", e);
                }
            });
        
        analysis.put("top_contacts", topContacts);
        analysis.put("total_unique_contacts", contactPatterns.size());
        
        return analysis;
    }
    
    private JSONObject generateMobilityAnalysis() throws JSONException {
        JSONObject analysis = new JSONObject();
        
        // Calculate mobility metrics
        double homeBaseRadius = calculateHomeBaseRadius();
        List<String> travelPatterns = analyzeTravelPatterns();
        boolean isHighMobility = totalDistanceTraveled > 10000; // 10km threshold
        
        analysis.put("home_base_radius", homeBaseRadius);
        analysis.put("is_high_mobility", isHighMobility);
        analysis.put("travel_patterns", new JSONArray(travelPatterns));
        analysis.put("average_daily_distance", calculateAverageDailyDistance());
        
        return analysis;
    }
    
    private JSONObject generateEnvironmentalAnalysis() throws JSONException {
        JSONObject analysis = new JSONObject();
        
        // Analyze environmental preferences
        Map<String, Object> preferences = new HashMap<>();
        for (EnvironmentalContext context : environmentalHistory) {
            preferences.put(context.getContext(), context.getValue());
        }
        
        analysis.put("environmental_preferences", new JSONObject(preferences));
        analysis.put("context_data_points", environmentalHistory.size());
        
        return analysis;
    }
    
    private JSONObject generateRiskAssessment() throws JSONException {
        JSONObject assessment = new JSONObject();
        
        // Calculate risk factors
        int riskScore = 0;
        List<String> riskFactors = new ArrayList<>();
        
        // High mobility risk
        if (totalDistanceTraveled > 50000) {
            riskScore += 20;
            riskFactors.add("High mobility pattern detected");
        }
        
        // Unusual activity hours
        if (hasUnusualActivityHours()) {
            riskScore += 15;
            riskFactors.add("Unusual activity hours");
        }
        
        // High contact diversity
        if (contactPatterns.size() > 100) {
            riskScore += 10;
            riskFactors.add("High contact diversity");
        }
        
        assessment.put("risk_score", riskScore);
        assessment.put("risk_level", getRiskLevel(riskScore));
        assessment.put("risk_factors", new JSONArray(riskFactors));
        
        return assessment;
    }
    
    // Helper methods
    
    private void updateAverageSpeed(float speed) {
        if (locationHistory.size() > 0) {
            double totalSpeed = 0;
            for (LocationDataPoint point : locationHistory) {
                totalSpeed += point.getSpeed();
            }
            averageSpeed = totalSpeed / locationHistory.size();
        }
    }
    
    private void updateTemporalPatterns(Location location) {
        java.util.Calendar calendar = java.util.Calendar.getInstance();
        int hour = calendar.get(java.util.Calendar.HOUR_OF_DAY);
        int dayOfWeek = calendar.get(java.util.Calendar.DAY_OF_WEEK);
        
        hourlyActivity.get(hour).incrementActivity();
        dailyActivity.get(dayOfWeek).incrementActivity();
    }
    
    private void analyzeMobilityPatterns(LocationDataPoint dataPoint) {
        behavioralMetrics.updateMobilityMetrics(dataPoint);
    }
    
    private JSONArray findMostActiveHours() {
        JSONArray activeHours = new JSONArray();
        hourlyActivity.entrySet().stream()
            .sorted((e1, e2) -> Integer.compare(e2.getValue().getActivityCount(), e1.getValue().getActivityCount()))
            .limit(5)
            .forEach(entry -> activeHours.put(entry.getKey()));
        return activeHours;
    }
    
    private JSONArray findMostActiveDays() {
        JSONArray activeDays = new JSONArray();
        dailyActivity.entrySet().stream()
            .sorted((e1, e2) -> Integer.compare(e2.getValue().getActivityCount(), e1.getValue().getActivityCount()))
            .limit(3)
            .forEach(entry -> activeDays.put(entry.getKey()));
        return activeDays;
    }
    
    private double calculateHomeBaseRadius() {
        if (locationHistory.size() < 10) return 0;
        
        // Find the most frequent location as potential home base
        String homeBase = locationFrequency.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("");
        
        if (homeBase.isEmpty()) return 0;
        
        String[] coords = homeBase.split(",");
        double homeLatitude = Double.parseDouble(coords[0]);
        double homeLongitude = Double.parseDouble(coords[1]);
        
        // Calculate average distance from home base
        double totalDistance = 0;
        int count = 0;
        
        for (LocationDataPoint point : locationHistory) {
            double distance = calculateDistance(homeLatitude, homeLongitude, point.getLatitude(), point.getLongitude());
            totalDistance += distance;
            count++;
        }
        
        return count > 0 ? totalDistance / count : 0;
    }
    
    private List<String> analyzeTravelPatterns() {
        List<String> patterns = new ArrayList<>();
        
        if (averageSpeed > 5) {
            patterns.add("Frequent vehicle travel");
        }
        if (averageSpeed < 2) {
            patterns.add("Primarily walking/stationary");
        }
        if (locationFrequency.size() > 50) {
            patterns.add("Highly varied locations");
        }
        if (totalDistanceTraveled > 1000) {
            patterns.add("Long-distance travel");
        }
        
        return patterns;
    }
    
    private double calculateAverageDailyDistance() {
        if (locationHistory.isEmpty()) return 0;
        
        long firstTimestamp = locationHistory.get(0).getTimestamp();
        long lastTimestamp = locationHistory.get(locationHistory.size() - 1).getTimestamp();
        long daysDiff = (lastTimestamp - firstTimestamp) / (24 * 60 * 60 * 1000);
        
        return daysDiff > 0 ? totalDistanceTraveled / daysDiff : totalDistanceTraveled;
    }
    
    private boolean hasUnusualActivityHours() {
        // Check for significant activity between 10 PM and 6 AM
        int nightActivity = 0;
        for (int i = 22; i <= 23; i++) {
            nightActivity += hourlyActivity.get(i).getActivityCount();
        }
        for (int i = 0; i <= 6; i++) {
            nightActivity += hourlyActivity.get(i).getActivityCount();
        }
        
        int totalActivity = hourlyActivity.values().stream().mapToInt(ActivityPattern::getActivityCount).sum();
        return totalActivity > 0 && (double) nightActivity / totalActivity > 0.3;
    }
    
    private String getRiskLevel(int riskScore) {
        if (riskScore < 10) return "Low";
        if (riskScore < 30) return "Medium";
        if (riskScore < 50) return "High";
        return "Critical";
    }
    
    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        // Haversine formula for distance calculation
        final int R = 6371; // Radius of the earth in km
        
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        double distance = R * c * 1000; // convert to meters
        
        return distance;
    }
    
    // Inner classes for data structures
    
    private static class LocationDataPoint {
        private double latitude;
        private double longitude;
        private float accuracy;
        private float speed;
        private float distance;
        private long timestamp;
        
        public LocationDataPoint(double latitude, double longitude, float accuracy, float speed, float distance, long timestamp) {
            this.latitude = latitude;
            this.longitude = longitude;
            this.accuracy = accuracy;
            this.speed = speed;
            this.distance = distance;
            this.timestamp = timestamp;
        }
        
        // Getters
        public double getLatitude() { return latitude; }
        public double getLongitude() { return longitude; }
        public float getAccuracy() { return accuracy; }
        public float getSpeed() { return speed; }
        public float getDistance() { return distance; }
        public long getTimestamp() { return timestamp; }
    }
    
    private static class ActivityPattern {
        private int activityCount;
        private long lastActivity;
        
        public ActivityPattern() {
            this.activityCount = 0;
            this.lastActivity = 0;
        }
        
        public void incrementActivity() {
            activityCount++;
            lastActivity = System.currentTimeMillis();
        }
        
        public int getActivityCount() { return activityCount; }
        
        public JSONObject toJSON() throws JSONException {
            JSONObject json = new JSONObject();
            json.put("activity_count", activityCount);
            json.put("last_activity", lastActivity);
            return json;
        }
    }
    
    private static class ContactPattern {
        private String identifier;
        private Map<String, Integer> contactTypes; // SMS, call, etc.
        private int totalContacts;
        private long firstContact;
        private long lastContact;
        
        public ContactPattern(String identifier) {
            this.identifier = identifier;
            this.contactTypes = new HashMap<>();
            this.totalContacts = 0;
            this.firstContact = System.currentTimeMillis();
            this.lastContact = System.currentTimeMillis();
        }
        
        public void addContact(String type, long timestamp) {
            contactTypes.put(type, contactTypes.getOrDefault(type, 0) + 1);
            totalContacts++;
            lastContact = timestamp;
        }
        
        public int getTotalContacts() { return totalContacts; }
        
        public JSONObject toJSON() throws JSONException {
            JSONObject json = new JSONObject();
            json.put("identifier", identifier);
            json.put("total_contacts", totalContacts);
            json.put("contact_types", new JSONObject(contactTypes));
            json.put("first_contact", firstContact);
            json.put("last_contact", lastContact);
            return json;
        }
    }
    
    private static class EnvironmentalContext {
        private String context;
        private Object value;
        private long timestamp;
        
        public EnvironmentalContext(String context, Object value, long timestamp) {
            this.context = context;
            this.value = value;
            this.timestamp = timestamp;
        }
        
        public String getContext() { return context; }
        public Object getValue() { return value; }
        public long getTimestamp() { return timestamp; }
    }
    
    private static class BehavioralMetrics {
        private double mobilityScore;
        private double socialScore;
        private double routineScore;
        private long analysisTimestamp;
        
        public void updateMobilityMetrics(LocationDataPoint dataPoint) {
            // Update mobility scoring based on movement patterns
            mobilityScore = (mobilityScore * 0.9) + (dataPoint.getSpeed() * 0.1);
            analysisTimestamp = System.currentTimeMillis();
        }
        
        public JSONObject toJSON() throws JSONException {
            JSONObject json = new JSONObject();
            json.put("mobility_score", mobilityScore);
            json.put("social_score", socialScore);
            json.put("routine_score", routineScore);
            json.put("analysis_timestamp", analysisTimestamp);
            return json;
        }
    }
}
